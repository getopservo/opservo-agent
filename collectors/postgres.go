package collectors

import (
	"context"
	"log/slog"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/getopservo/opservo-agent/paths"
)

// PostgresStat is one PostgreSQL instance's health + configuration facts,
// read from pg_stat_* views (and pg_stat_statements when installed).
type PostgresStat struct {
	Name          string `json:"name"`
	Source        string `json:"source"`             // host | container | remote
	Database      string `json:"database,omitempty"` // DB the per-database facts (top_slow, bloat) came from
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	Replica       bool   `json:"replica"` // pg_is_in_recovery()

	Connections     int     `json:"connections"`
	MaxConnections  int     `json:"max_connections"`
	ConnUsagePct    float64 `json:"conn_usage_pct"`
	Active          int     `json:"active"`
	IdleInTxn       int     `json:"idle_in_txn"`
	LongRunningNum  int     `json:"long_running_count"` // active client queries ≥ 5 s
	LongestQuerySec int64   `json:"longest_query_seconds"`

	// Cache hit % across all databases (blks_hit / (hit+read)). Nil until
	// the cluster has served reads since its last stats reset.
	CacheHitPct *float64 `json:"cache_hit_pct,omitempty"`
	CacheReads  int64    `json:"cache_reads,omitempty"` // blks_hit+blks_read behind CacheHitPct
	Deadlocks   int64    `json:"deadlocks"`             // cumulative since stats reset
	TempBytes   int64    `json:"temp_bytes"`            // cumulative spill-to-disk bytes
	TxnPerSec   float64  `json:"txn_per_sec"`           // commits+rollbacks / uptime
	StatsAgeSec int64    `json:"stats_age_seconds,omitempty"`

	SharedBuffersBytes      int64 `json:"shared_buffers_bytes"`
	WorkMemBytes            int64 `json:"work_mem_bytes"`
	EffectiveCacheSizeBytes int64 `json:"effective_cache_size_bytes"`

	StatStatements bool               `json:"pg_stat_statements"` // extension installed in the connected DB
	TopSlow        []SlowQueryPattern `json:"top_slow,omitempty"` // from pg_stat_statements
	LongRunning    []RunningQuery     `json:"long_running,omitempty"`
	BloatedTables  []PostgresBloat    `json:"bloated_tables,omitempty"`
}

// PostgresBloat is a table whose dead-tuple count suggests autovacuum is behind.
type PostgresBloat struct {
	Table        string `json:"table"`
	DeadTuples   int64  `json:"dead_tuples"`
	LiveTuples   int64  `json:"live_tuples"`
	SinceVacuumS int64  `json:"seconds_since_vacuum"` // -1 = never vacuumed
}

// PostgresInfo: per-instance PostgreSQL facts. Credential-respecting like the
// MySQL collector: the host path runs psql as the local `postgres` OS user
// (peer auth), or uses the operator's OWN /etc/opservo/pg.conf — a single
// libpq connection URI/keywords line pointing at a read-only monitoring role
// (works for a private RDS reachable from this box). The agent never reads
// the application's .env.
type PostgresInfo struct {
	Available bool           `json:"available"`
	Instances []PostgresStat `json:"instances"`
}

type PostgresCollector struct{}

func NewPostgresCollector() *PostgresCollector { return &PostgresCollector{} }
func (p *PostgresCollector) Name() string      { return "postgres" }

func pgConfigPath() string { return paths.ConfigFile("pg.conf") }

var pgContainerRe = regexp.MustCompile(`(?i)postgres|timescale|pgvector|supabase|pgsql`)

// One round-trip of key\tvalue facts. Everything here is readable by any role
// with pg_monitor (or any login role for most rows).
const pgFactsQuery = `SELECT 'version', current_setting('server_version')
UNION ALL SELECT 'max_connections', current_setting('max_connections')
UNION ALL SELECT 'shared_buffers', pg_size_bytes(current_setting('shared_buffers'))::text
UNION ALL SELECT 'work_mem', pg_size_bytes(current_setting('work_mem'))::text
UNION ALL SELECT 'effective_cache_size', pg_size_bytes(current_setting('effective_cache_size'))::text
UNION ALL SELECT 'uptime', extract(epoch from now()-pg_postmaster_start_time())::bigint::text
UNION ALL SELECT 'replica', pg_is_in_recovery()::text
UNION ALL SELECT 'connections', count(*)::text FROM pg_stat_activity WHERE backend_type='client backend'
UNION ALL SELECT 'active', count(*)::text FROM pg_stat_activity WHERE backend_type='client backend' AND state='active'
UNION ALL SELECT 'idle_in_txn', count(*)::text FROM pg_stat_activity WHERE state LIKE 'idle in transaction%'
UNION ALL SELECT 'long_running', count(*)::text FROM pg_stat_activity WHERE backend_type='client backend' AND state='active' AND now()-query_start > interval '5 seconds' AND pid<>pg_backend_pid()
UNION ALL SELECT 'longest', coalesce(max(extract(epoch from now()-query_start)),0)::bigint::text FROM pg_stat_activity WHERE backend_type='client backend' AND state='active' AND pid<>pg_backend_pid()
UNION ALL SELECT 'blks_hit', coalesce(sum(blks_hit),0)::text FROM pg_stat_database
UNION ALL SELECT 'blks_read', coalesce(sum(blks_read),0)::text FROM pg_stat_database
UNION ALL SELECT 'deadlocks', coalesce(sum(deadlocks),0)::text FROM pg_stat_database
UNION ALL SELECT 'temp_bytes', coalesce(sum(temp_bytes),0)::text FROM pg_stat_database
UNION ALL SELECT 'xacts', coalesce(sum(xact_commit+xact_rollback),0)::text FROM pg_stat_database
UNION ALL SELECT 'stats_age', coalesce(extract(epoch from now()-min(stats_reset)),0)::bigint::text FROM pg_stat_database WHERE stats_reset IS NOT NULL`

// Per-database facts run against the "main" DB: on a host install the
// maintenance DB `postgres` holds no app tables, so the largest user
// database is chosen instead. Containers/remote already connect to the app DB.
const pgLargestDBQuery = `SELECT datname FROM pg_database WHERE NOT datistemplate AND datname <> 'postgres' ORDER BY pg_database_size(datname) DESC LIMIT 1`
const pgStatStatementsPresentQuery = `SELECT count(*) FROM pg_extension WHERE extname='pg_stat_statements'`

const pgLongRunningQuery = `SELECT extract(epoch from now()-query_start)::bigint, state, left(regexp_replace(query,'\s+',' ','g'),400) ` +
	`FROM pg_stat_activity WHERE backend_type='client backend' AND state='active' AND now()-query_start > interval '5 seconds' AND pid<>pg_backend_pid() ORDER BY 1 DESC LIMIT 5`

const pgBloatQuery = `SELECT schemaname||'.'||relname, n_dead_tup, n_live_tup, coalesce(extract(epoch from now()-greatest(last_autovacuum,last_vacuum)),-1)::bigint ` +
	`FROM pg_stat_user_tables WHERE n_dead_tup > 10000 AND n_dead_tup > n_live_tup*0.2 ORDER BY n_dead_tup DESC LIMIT 3`

// PG13+ column names; the ≤12 variant is tried when this errors.
const pgStatStatementsQuery = `SELECT calls, round(total_exec_time)::bigint, round(max_exec_time)::bigint, coalesce(rows,0), left(regexp_replace(query,'\s+',' ','g'),400) ` +
	`FROM pg_stat_statements WHERE calls > 1 AND query !~* '^(begin|commit|rollback|set |show |deallocate|discard)' ORDER BY total_exec_time DESC LIMIT 3`
const pgStatStatementsQueryLegacy = `SELECT calls, round(total_time)::bigint, round(max_time)::bigint, coalesce(rows,0), left(regexp_replace(query,'\s+',' ','g'),400) ` +
	`FROM pg_stat_statements WHERE calls > 1 AND query !~* '^(begin|commit|rollback|set |show |deallocate|discard)' ORDER BY total_time DESC LIMIT 3`

// pgRunner executes one SQL statement (against db when non-empty, else the
// connection's default) and returns tab-separated rows.
type pgRunner func(db, sql string) (string, error)

func psqlArgs(db, sql string) []string {
	args := []string{"-X", "-At", "-F", "\t", "-v", "ON_ERROR_STOP=1"}
	if db != "" {
		args = append(args, "-d", db)
	}
	return append(args, "-c", sql)
}

func (p *PostgresCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &PostgresInfo{Instances: []PostgresStat{}}

	// 1. Operator-provided connection (read-only monitoring role; may be remote).
	// The connection string is passed to psql as libpq PG* environment
	// variables, never on argv (the password would show in `ps` otherwise —
	// see pgconn.go). An unparseable line is skipped, never fed to argv.
	if conn, err := os.ReadFile(pgConfigPath()); err == nil {
		if line := strings.TrimSpace(firstNonCommentLine(string(conn))); line != "" && hasBinary("psql") {
			if env, perr := pgConnEnv(line); perr != nil {
				slog.Warn("postgres collector: ignoring "+pgConfigPath(), "error", perr)
			} else {
				run := func(_ string, sql string) (string, error) { // connection already names the DB
					out, err := runCmdEnvTimeout(ctx, 6*time.Second, env, "psql", psqlArgs("", sql)...)
					return string(out), err
				}
				if st, ok := collectPostgres(run, false); ok {
					st.Name, st.Source = "configured", "remote"
					info.Available = true
					info.Instances = append(info.Instances, st)
				}
			}
		}
	}

	// 2. Local server via peer auth as the postgres OS user.
	if hasBinary("psql") && osUserExists("postgres") {
		var wrap []string
		switch {
		case hasBinary("setpriv"):
			// Preferred: a plain uid/gid switch with no PAM session. runuser/su
			// open a PAM session per call, and with ~5 psql calls per heartbeat
			// that put ~10 "session opened/closed for user postgres" lines a
			// minute into the agent's own journal — enough to bury a real error.
			wrap = []string{"setpriv", "--reuid=postgres", "--regid=postgres", "--init-groups", "--", "psql"}
		case hasBinary("runuser"):
			wrap = []string{"runuser", "-u", "postgres", "--", "psql"}
		case hasBinary("su"):
			wrap = nil // handled below (needs a shell string)
		}
		run := func(db, sql string) (string, error) {
			var out []byte
			var err error
			if wrap != nil {
				out, err = runCmdTimeout(ctx, 6*time.Second, wrap[0], append(wrap[1:], psqlArgs(db, sql)...)...)
			} else {
				cmd := "psql"
				for _, a := range psqlArgs(db, sql) {
					cmd += " " + shellQuote(a)
				}
				out, err = runCmdTimeout(ctx, 6*time.Second, "su", "-s", "/bin/sh", "postgres", "-c", cmd)
			}
			return string(out), err
		}
		if st, ok := collectPostgres(run, true); ok {
			st.Name, st.Source = "localhost", "host"
			info.Available = true
			info.Instances = append(info.Instances, st)
		}
	}

	// 3. Containers (official image conventions: POSTGRES_USER / POSTGRES_DB env).
	for _, c := range listContainers(ctx) {
		if !pgContainerRe.MatchString(c.Name) && !pgContainerRe.MatchString(c.Image) {
			continue
		}
		run := func(db, sql string) (string, error) {
			dbArg := `"${POSTGRES_DB:-${POSTGRES_USER:-postgres}}"`
			if db != "" {
				dbArg = shellQuote(db)
			}
			cmd := `psql -X -At -F '	' -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d ` + dbArg + " -c " + shellQuote(sql) + " 2>/dev/null"
			out, err := runCmdTimeout(ctx, 6*time.Second, "docker", "exec", c.Name, "sh", "-c", cmd)
			return string(out), err
		}
		if st, ok := collectPostgres(run, false); ok {
			st.Name, st.Source = c.Name, "container"
			info.Available = true
			info.Instances = append(info.Instances, st)
		}
	}

	return info, nil
}

func firstNonCommentLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			return l
		}
	}
	return ""
}

func osUserExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

// collectPostgres drives one instance through the runner. ok=false when the
// facts query fails (no server, auth refused) so the caller skips quietly.
// pickDB: choose the largest user database for the per-database facts
// (host installs connect to the empty maintenance DB by default).
func collectPostgres(run pgRunner, pickDB bool) (PostgresStat, bool) {
	out, err := run("", pgFactsQuery)
	if err != nil || strings.TrimSpace(out) == "" {
		return PostgresStat{}, false
	}
	st := parsePostgresFacts(out)
	if st.Version == "" {
		return PostgresStat{}, false
	}
	if lr, err := run("", pgLongRunningQuery); err == nil {
		st.LongRunning = parsePostgresLongRunning(lr)
	}
	db := ""
	if pickDB {
		if name, err := run("", pgLargestDBQuery); err == nil {
			db = strings.TrimSpace(name)
			st.Database = db
		}
	}
	if present, err := run(db, pgStatStatementsPresentQuery); err == nil {
		n, _ := strconv.Atoi(strings.TrimSpace(present))
		st.StatStatements = n > 0
	}
	if bl, err := run(db, pgBloatQuery); err == nil {
		st.BloatedTables = parsePostgresBloat(bl)
	}
	if st.StatStatements {
		ss, err := run(db, pgStatStatementsQuery)
		if err != nil {
			ss, err = run(db, pgStatStatementsQueryLegacy)
		}
		if err == nil {
			st.TopSlow = parsePostgresStatStatements(ss)
		}
	}
	return st, true
}

// parsePostgresFacts parses the key\tvalue rows of pgFactsQuery. Pure + tested.
func parsePostgresFacts(out string) PostgresStat {
	vals := map[string]string{}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if k, v, ok := strings.Cut(line, "\t"); ok {
			vals[k] = strings.TrimSpace(v)
		}
	}
	atoi := func(k string) int { n, _ := strconv.Atoi(vals[k]); return n }
	atoi64 := func(k string) int64 { n, _ := strconv.ParseInt(vals[k], 10, 64); return n }
	atof := func(k string) float64 { f, _ := strconv.ParseFloat(vals[k], 64); return f }
	var st PostgresStat
	st.Version = vals["version"]
	st.MaxConnections = atoi("max_connections")
	st.SharedBuffersBytes = atoi64("shared_buffers")
	st.WorkMemBytes = atoi64("work_mem")
	st.EffectiveCacheSizeBytes = atoi64("effective_cache_size")
	st.UptimeSeconds = atoi64("uptime")
	st.Replica = vals["replica"] == "t" || vals["replica"] == "true"
	st.Connections = atoi("connections")
	st.Active = atoi("active")
	st.IdleInTxn = atoi("idle_in_txn")
	st.LongRunningNum = atoi("long_running")
	st.LongestQuerySec = atoi64("longest")
	st.Deadlocks = atoi64("deadlocks")
	st.TempBytes = atoi64("temp_bytes")
	st.StatsAgeSec = atoi64("stats_age")
	if hit, rd := atof("blks_hit"), atof("blks_read"); hit+rd > 0 {
		pct := hit / (hit + rd) * 100
		st.CacheHitPct = &pct
		st.CacheReads = int64(hit + rd)
	}
	if st.MaxConnections > 0 {
		st.ConnUsagePct = float64(st.Connections) / float64(st.MaxConnections) * 100
	}
	if st.UptimeSeconds > 0 {
		st.TxnPerSec = atof("xacts") / float64(st.UptimeSeconds)
	}
	return st
}

func parsePostgresLongRunning(out string) []RunningQuery {
	var rows []RunningQuery
	for _, raw := range strings.Split(out, "\n") {
		f := strings.SplitN(strings.TrimRight(raw, "\r"), "\t", 3)
		if len(f) < 3 {
			continue
		}
		secs, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		if q := normalizeQuery(f[2]); q != "" {
			rows = append(rows, RunningQuery{Seconds: secs, State: f[1], Query: q})
		}
	}
	return rows
}

func parsePostgresBloat(out string) []PostgresBloat {
	var rows []PostgresBloat
	for _, raw := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(raw, "\r"), "\t")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		dead, _ := strconv.ParseInt(f[1], 10, 64)
		live, _ := strconv.ParseInt(f[2], 10, 64)
		since, _ := strconv.ParseInt(f[3], 10, 64)
		rows = append(rows, PostgresBloat{Table: f[0], DeadTuples: dead, LiveTuples: live, SinceVacuumS: since})
	}
	return rows
}

// parsePostgresStatStatements parses `calls\ttotal_ms\tmax_ms\trows\tquery` rows.
func parsePostgresStatStatements(out string) []SlowQueryPattern {
	var rows []SlowQueryPattern
	for _, raw := range strings.Split(out, "\n") {
		f := strings.SplitN(strings.TrimRight(raw, "\r"), "\t", 5)
		if len(f) < 5 {
			continue
		}
		calls, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil || calls <= 0 {
			continue
		}
		totalMs, _ := strconv.ParseFloat(f[1], 64)
		maxMs, _ := strconv.ParseFloat(f[2], 64)
		nrows, _ := strconv.ParseInt(f[3], 10, 64)
		q := normalizeQuery(f[4])
		if q == "" {
			continue
		}
		rows = append(rows, SlowQueryPattern{
			Pattern:     q,
			Count:       calls,
			TotalSecs:   totalMs / 1000,
			AvgSeconds:  totalMs / 1000 / float64(calls),
			MaxSeconds:  maxMs / 1000,
			RowsExamAvg: nrows / calls,
		})
	}
	return rows
}
