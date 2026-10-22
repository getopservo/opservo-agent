package collectors

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/getopservo/opservo-agent/paths"
)

// MySQLStat is one MySQL/MariaDB instance's key health metrics (SHOW GLOBAL
// STATUS / VARIABLES). All counters are cumulative-since-start; gauges are current.
type MySQLStat struct {
	Name             string  `json:"name"`
	Source           string  `json:"source"` // host | container
	Version          string  `json:"version"`
	ThreadsConnected int     `json:"threads_connected"`
	ThreadsRunning   int     `json:"threads_running"`
	MaxConnections   int     `json:"max_connections"`
	ConnUsagePct     float64 `json:"conn_usage_pct"`
	Questions        int64   `json:"questions"`        // cumulative
	SlowQueries      int64   `json:"slow_queries"`     // cumulative
	AbortedConnects  int64   `json:"aborted_connects"` // cumulative
	UptimeSeconds    int64   `json:"uptime_seconds"`
	QueriesPerSec    float64 `json:"queries_per_sec"` // avg since start (Questions/Uptime)

	// ── Configuration facts (database insights) ──────────────────────
	SlowQueryLog     bool    `json:"slow_query_log"`
	LongQueryTime    float64 `json:"long_query_time"`
	SlowQueryLogFile string  `json:"slow_query_log_file,omitempty"`
	BufferPoolBytes  int64   `json:"buffer_pool_bytes"`
	// InnoDB buffer-pool hit %: read_requests served from memory. Nil when the
	// counters are zero (fresh start) — absent ≠ 100%.
	BufferPoolHitPct *float64 `json:"buffer_pool_hit_pct,omitempty"`
	// Logical read requests behind BufferPoolHitPct (its sample size).
	BufferPoolReadRequests int64 `json:"buffer_pool_read_requests,omitempty"`
	// Share of implicit temp tables that spilled to disk. Nil when none created.
	TmpDiskTablePct *float64 `json:"tmp_disk_table_pct,omitempty"`
	TmpTables       int64    `json:"tmp_tables,omitempty"` // Created_tmp_tables behind TmpDiskTablePct
	SelectFullJoin  int64    `json:"select_full_join"`     // joins without usable index (cumulative)

	// ── Live + historical slow queries (normalized, literal-free) ────────
	LongRunning  []RunningQuery     `json:"long_running,omitempty"`   // active ≥ 5 s right now
	TopSlow      []SlowQueryPattern `json:"top_slow,omitempty"`       // from the slow log (host only)
	SlowLogError string             `json:"slow_log_error,omitempty"` // why top_slow is empty, if known
}

// MySQLInfo: per-instance MySQL metrics. OPT-IN and credential-respecting: the
// agent uses its OWN /etc/opservo/mysql.cnf (a [client] option file the
// operator creates with a read-only monitoring user) — it NEVER reads the app's
// .env. Falls back to local socket auth (root@localhost via auth_socket).
type MySQLInfo struct {
	Available bool        `json:"available"`
	Instances []MySQLStat `json:"instances"`
}

type MySQLCollector struct{}

func NewMySQLCollector() *MySQLCollector { return &MySQLCollector{} }
func (m *MySQLCollector) Name() string   { return "mysql" }

// mysqlConfigPath is read on each collect, so a migrated box picks up the new dir.
func mysqlConfigPath() string { return paths.ConfigFile("mysql.cnf") }

const mysqlQuery = "SHOW GLOBAL STATUS; " +
	"SHOW GLOBAL VARIABLES WHERE Variable_name IN ('max_connections','slow_query_log','long_query_time','slow_query_log_file','innodb_buffer_pool_size','log_output','datadir'); " +
	"SELECT VERSION()"

// Statements running ≥ 5 s right now. INFO is flattened + truncated in SQL so
// the tab-separated output stays one row per query; literals are stripped
// agent-side by normalizeQuery before anything is shipped.
const mysqlProcesslistQuery = "SELECT TIME, IFNULL(STATE,''), LEFT(REPLACE(REPLACE(REPLACE(INFO,'\\n',' '),'\\r',' '),'\\t',' '),400) " +
	"FROM information_schema.PROCESSLIST WHERE COMMAND NOT IN ('Sleep','Binlog Dump','Daemon','Connect') " +
	"AND TIME >= 5 AND INFO IS NOT NULL AND ID <> CONNECTION_ID() ORDER BY TIME DESC LIMIT 5"

// Slow-log tail read per heartbeat: enough for hours of a normal log, small
// enough to parse in milliseconds.
const mysqlSlowLogTailBytes = 1 << 20

var mysqlContainerRe = regexp.MustCompile(`(?i)mysql|mariadb|percona`)

func mysqlClientBin() string {
	if hasBinary("mysql") {
		return "mysql"
	}
	if hasBinary("mariadb") {
		return "mariadb"
	}
	return ""
}

func (m *MySQLCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &MySQLInfo{Instances: []MySQLStat{}}

	// 1. Local MySQL via the host client (opt-in cnf, else socket auth).
	if bin := mysqlClientBin(); bin != "" {
		base := []string{"--connect-timeout=2", "-N", "-B"}
		if _, err := os.Stat(mysqlConfigPath()); err == nil {
			base = append([]string{"--defaults-extra-file=" + mysqlConfigPath()}, base...)
		}
		run := func(q string) (string, error) {
			out, err := runCmdTimeout(ctx, 5*time.Second, bin, append(append([]string{}, base...), "-e", q)...)
			return string(out), err
		}
		if out, err := run(mysqlQuery); err == nil && len(out) > 0 {
			st, vars := parseMySQLStatus(out)
			if st.UptimeSeconds > 0 {
				st.Name, st.Source = "localhost", "host"
				if pl, err := run(mysqlProcesslistQuery); err == nil {
					st.LongRunning = parseMySQLProcesslist(pl)
				}
				m.readSlowLog(&st, vars)
				info.Available = true
				info.Instances = append(info.Instances, st)
			}
		}
	}

	// 2. Containerized MySQL/MariaDB (best-effort exec; needs an in-container
	//    monitoring user or socket auth — skips quietly otherwise). The slow log
	//    lives inside the container, so only live facts are collected there.
	for _, c := range listContainers(ctx) {
		if !mysqlContainerRe.MatchString(c.Name) && !mysqlContainerRe.MatchString(c.Image) {
			continue
		}
		run := func(q string) (string, error) {
			out, err := runCmdTimeout(ctx, 5*time.Second, "docker", "exec", c.Name, "sh", "-c",
				"mysql --connect-timeout=2 -N -B -e "+shellQuote(q)+" 2>/dev/null")
			return string(out), err
		}
		out, err := run(mysqlQuery)
		if err != nil || len(out) == 0 {
			continue
		}
		st, _ := parseMySQLStatus(out)
		if st.UptimeSeconds == 0 {
			continue
		}
		st.Name, st.Source = c.Name, "container"
		if pl, err := run(mysqlProcesslistQuery); err == nil {
			st.LongRunning = parseMySQLProcesslist(pl)
		}
		info.Available = true
		info.Instances = append(info.Instances, st)
	}

	return info, nil
}

// readSlowLog fills TopSlow from the on-disk slow log when the log is on and
// written to a FILE (log_output may be TABLE or NONE). Never fatal.
func (m *MySQLCollector) readSlowLog(st *MySQLStat, vars map[string]string) {
	if !st.SlowQueryLog {
		return
	}
	if lo := strings.ToUpper(vars["log_output"]); lo != "" && !strings.Contains(lo, "FILE") {
		st.SlowLogError = "log_output=" + lo + " (not FILE)"
		return
	}
	path := vars["slow_query_log_file"]
	if path == "" {
		return
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(vars["datadir"], path)
	}
	tail, err := readFileTail(path, mysqlSlowLogTailBytes)
	if err != nil {
		st.SlowLogError = "cannot read " + path
		return
	}
	st.TopSlow = parseMySQLSlowLog(tail, 3)
}

// readFileTail returns the last n bytes of a file (or the whole file if smaller).
func readFileTail(path string, n int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fi.Size() > n {
		if _, err := f.Seek(fi.Size()-n, io.SeekStart); err != nil {
			return "", err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, n))
	if err != nil {
		return "", err
	}
	s := string(b)
	// Drop the (probably partial) first line when we started mid-file.
	if fi.Size() > n {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
	}
	return s, nil
}

var mysqlVersionRe = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// parseMySQLStatus parses tab-separated `name\tvalue` lines from SHOW GLOBAL
// STATUS/VARIABLES (+ a lone VERSION() line). Returns the stat plus the raw
// variable map (for slow-log path resolution). Pure + unit-tested.
func parseMySQLStatus(out string) (MySQLStat, map[string]string) {
	vals := map[string]string{}
	var st MySQLStat
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "\t")
		if ok {
			vals[k] = v
		} else if mysqlVersionRe.MatchString(line) {
			st.Version = strings.TrimSpace(line)
		}
	}
	atoi := func(k string) int { n, _ := strconv.Atoi(vals[k]); return n }
	atoi64 := func(k string) int64 { n, _ := strconv.ParseInt(vals[k], 10, 64); return n }
	atof := func(k string) float64 { f, _ := strconv.ParseFloat(vals[k], 64); return f }
	st.ThreadsConnected = atoi("Threads_connected")
	st.ThreadsRunning = atoi("Threads_running")
	st.MaxConnections = atoi("max_connections")
	st.Questions = atoi64("Questions")
	st.SlowQueries = atoi64("Slow_queries")
	st.AbortedConnects = atoi64("Aborted_connects")
	st.UptimeSeconds = atoi64("Uptime")
	st.SlowQueryLog = strings.EqualFold(vals["slow_query_log"], "ON") || vals["slow_query_log"] == "1"
	st.LongQueryTime = atof("long_query_time")
	st.SlowQueryLogFile = vals["slow_query_log_file"]
	st.BufferPoolBytes = atoi64("innodb_buffer_pool_size")
	st.SelectFullJoin = atoi64("Select_full_join")
	if req, rd := atof("Innodb_buffer_pool_read_requests"), atof("Innodb_buffer_pool_reads"); req > 0 {
		hit := (1 - rd/req) * 100
		if hit < 0 {
			hit = 0
		}
		st.BufferPoolHitPct = &hit
		st.BufferPoolReadRequests = int64(req)
	}
	if tmp, disk := atof("Created_tmp_tables"), atof("Created_tmp_disk_tables"); tmp > 0 {
		pct := disk / tmp * 100
		st.TmpDiskTablePct = &pct
		st.TmpTables = int64(tmp)
	}
	if st.MaxConnections > 0 {
		st.ConnUsagePct = float64(st.ThreadsConnected) / float64(st.MaxConnections) * 100
	}
	if st.UptimeSeconds > 0 {
		st.QueriesPerSec = float64(st.Questions) / float64(st.UptimeSeconds)
	}
	return st, vals
}

// parseMySQLProcesslist parses `TIME\tSTATE\tINFO` rows into normalized
// RunningQuery entries. Pure + unit-tested.
func parseMySQLProcesslist(out string) []RunningQuery {
	var rows []RunningQuery
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		f := strings.SplitN(line, "\t", 3)
		if len(f) < 3 {
			continue
		}
		secs, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		q := normalizeQuery(f[2])
		if q == "" {
			continue
		}
		rows = append(rows, RunningQuery{Seconds: secs, State: f[1], Query: q})
	}
	return rows
}

var (
	slowQueryTimeRe = regexp.MustCompile(`# Query_time:\s*([\d.]+)`)
	slowRowsExamRe  = regexp.MustCompile(`Rows_examined:\s*(\d+)`)
)

// parseMySQLSlowLog aggregates a MySQL/MariaDB slow-log text into the top-N
// query patterns by total time. Literals are stripped (normalizeQuery) so no
// customer data is retained. Pure + unit-tested.
func parseMySQLSlowLog(text string, topN int) []SlowQueryPattern {
	type agg struct {
		count      int64
		total, max float64
		rows       int64
	}
	byPattern := map[string]*agg{}
	var curTime float64
	var curRows int64
	var haveEntry bool
	var stmt []string

	flush := func() {
		if !haveEntry || len(stmt) == 0 {
			stmt = nil
			return
		}
		p := normalizeQuery(strings.Join(stmt, " "))
		stmt = nil
		if p == "" {
			return
		}
		a := byPattern[p]
		if a == nil {
			a = &agg{}
			byPattern[p] = a
		}
		a.count++
		a.total += curTime
		a.rows += curRows
		if curTime > a.max {
			a.max = curTime
		}
	}

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if m := slowQueryTimeRe.FindStringSubmatch(line); m != nil {
				flush()
				curTime, _ = strconv.ParseFloat(m[1], 64)
				curRows = 0
				if r := slowRowsExamRe.FindStringSubmatch(line); r != nil {
					curRows, _ = strconv.ParseInt(r[1], 10, 64)
				}
				haveEntry = true
			}
			continue
		}
		if !haveEntry {
			continue
		}
		lower := strings.ToLower(line)
		// Preamble lines the server writes before every statement.
		if strings.HasPrefix(lower, "set timestamp=") || strings.HasPrefix(lower, "use ") ||
			strings.HasPrefix(lower, "throttle:") || strings.HasPrefix(line, "/usr/") ||
			strings.HasPrefix(line, "Tcp port:") || strings.HasPrefix(line, "Time ") {
			continue
		}
		stmt = append(stmt, line)
	}
	flush()

	out := make([]SlowQueryPattern, 0, len(byPattern))
	for p, a := range byPattern {
		sp := SlowQueryPattern{Pattern: p, Count: a.count, TotalSecs: a.total, MaxSeconds: a.max}
		if a.count > 0 {
			sp.AvgSeconds = a.total / float64(a.count)
			sp.RowsExamAvg = a.rows / a.count
		}
		out = append(out, sp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalSecs != out[j].TotalSecs {
			return out[i].TotalSecs > out[j].TotalSecs
		}
		return out[i].Pattern < out[j].Pattern
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

// shellQuote single-quotes a string for `sh -c`.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
