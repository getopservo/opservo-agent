package collectors

import (
	"math"
	"strings"
	"testing"
)

func TestNormalizeQueryStripsLiterals(t *testing.T) {
	q := "SELECT *  FROM users\n WHERE email = 'a@b.com' AND id IN (1, 2, 3) AND age > 30 LIMIT 10;"
	got := normalizeQuery(q)
	want := "SELECT * FROM users WHERE email = ? AND id IN (?) AND age > ? LIMIT ?"
	if got != want {
		t.Fatalf("normalizeQuery:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(normalizeQuery(`INSERT INTO t (a,b) VALUES ('x', 1), ("y", 2)`), "x") {
		t.Fatal("string literal leaked through VALUES normalization")
	}
	long := "SELECT " + strings.Repeat("col, ", 200) + "x FROM t"
	if n := normalizeQuery(long); len(n) > maxQueryTextLen+len("…") {
		t.Fatalf("not truncated: %d", len(n))
	}
}

func TestParseMySQLStatusConfigFacts(t *testing.T) {
	out := "Uptime\t100\nInnodb_buffer_pool_read_requests\t1000\nInnodb_buffer_pool_reads\t50\n" +
		"Created_tmp_tables\t200\nCreated_tmp_disk_tables\t50\nSelect_full_join\t7\n" +
		"slow_query_log\tON\nlong_query_time\t2.000000\nslow_query_log_file\t/var/log/mysql/slow.log\n" +
		"innodb_buffer_pool_size\t134217728\nlog_output\tFILE\n"
	st, vars := parseMySQLStatus(out)
	if !st.SlowQueryLog || st.LongQueryTime != 2 || st.SlowQueryLogFile != "/var/log/mysql/slow.log" {
		t.Fatalf("slow-log facts wrong: %+v", st)
	}
	if st.BufferPoolBytes != 134217728 || st.SelectFullJoin != 7 {
		t.Fatalf("buffer/join facts wrong: %+v", st)
	}
	if st.BufferPoolHitPct == nil || math.Abs(*st.BufferPoolHitPct-95) > 0.001 {
		t.Fatalf("buffer pool hit = %v, want 95", st.BufferPoolHitPct)
	}
	if st.TmpDiskTablePct == nil || math.Abs(*st.TmpDiskTablePct-25) > 0.001 {
		t.Fatalf("tmp disk pct = %v, want 25", st.TmpDiskTablePct)
	}
	// Sample sizes behind both ratios, so the API can ignore ratios over a handful of events.
	if st.BufferPoolReadRequests != 1000 || st.TmpTables != 200 {
		t.Fatalf("sample sizes = %d reads / %d tmp tables, want 1000 / 200", st.BufferPoolReadRequests, st.TmpTables)
	}
	if vars["log_output"] != "FILE" {
		t.Fatalf("vars not returned: %v", vars)
	}
	// Absent counters must stay nil (absent ≠ 100 %).
	st2, _ := parseMySQLStatus("Uptime\t5\nslow_query_log\tOFF\n")
	if st2.BufferPoolHitPct != nil || st2.TmpDiskTablePct != nil || st2.SlowQueryLog {
		t.Fatalf("expected nil ratios + slow log off: %+v", st2)
	}
}

func TestParseMySQLProcesslist(t *testing.T) {
	out := "42\tSending data\tSELECT * FROM orders WHERE customer_id = 9182 AND status = 'paid'\n" +
		"7\t\tUPDATE sessions SET last_seen = 1700000000 WHERE token = 'abc'\n" +
		"garbage line\n"
	rows := parseMySQLProcesslist(out)
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d: %+v", len(rows), rows)
	}
	if rows[0].Seconds != 42 || rows[0].State != "Sending data" {
		t.Fatalf("row0 wrong: %+v", rows[0])
	}
	if strings.Contains(rows[0].Query, "9182") || strings.Contains(rows[1].Query, "abc") {
		t.Fatalf("literals leaked: %+v", rows)
	}
}

func TestParseMySQLSlowLog(t *testing.T) {
	log := `/usr/sbin/mysqld, Version: 8.0.36 (MySQL Community Server - GPL). started with:
Tcp port: 3306  Unix socket: /var/run/mysqld/mysqld.sock
Time                 Id Command    Argument
# Time: 2026-09-14T10:00:00.000000Z
# User@Host: app[app] @ localhost []  Id:    12
# Query_time: 3.500000  Lock_time: 0.000010 Rows_sent: 1  Rows_examined: 500000
use shop;
SET timestamp=1789000000;
SELECT * FROM orders WHERE customer_id = 1 AND status = 'paid';
# Time: 2026-09-14T10:00:05.000000Z
# User@Host: app[app] @ localhost []  Id:    13
# Query_time: 1.500000  Lock_time: 0.000010 Rows_sent: 1  Rows_examined: 300000
SET timestamp=1789000005;
SELECT * FROM orders
  WHERE customer_id = 2 AND status = 'paid';
# Time: 2026-09-14T10:00:09.000000Z
# User@Host: app[app] @ localhost []  Id:    14
# Query_time: 2.000000  Lock_time: 0.000010 Rows_sent: 10  Rows_examined: 10
SET timestamp=1789000009;
SELECT name FROM products WHERE id IN (1,2,3);
`
	top := parseMySQLSlowLog(log, 3)
	if len(top) != 2 {
		t.Fatalf("want 2 patterns, got %d: %+v", len(top), top)
	}
	first := top[0]
	if first.Count != 2 || math.Abs(first.TotalSecs-5) > 0.001 || math.Abs(first.AvgSeconds-2.5) > 0.001 || first.MaxSeconds != 3.5 {
		t.Fatalf("aggregation wrong: %+v", first)
	}
	if first.RowsExamAvg != 400000 {
		t.Fatalf("rows examined avg = %d", first.RowsExamAvg)
	}
	if first.Pattern != "SELECT * FROM orders WHERE customer_id = ? AND status = ?" {
		t.Fatalf("pattern = %q", first.Pattern)
	}
	if top[1].Pattern != "SELECT name FROM products WHERE id IN (?)" {
		t.Fatalf("pattern2 = %q", top[1].Pattern)
	}
	if got := parseMySQLSlowLog(log, 1); len(got) != 1 {
		t.Fatalf("topN not applied: %d", len(got))
	}
	if got := parseMySQLSlowLog("", 3); len(got) != 0 {
		t.Fatalf("empty log should yield nothing: %+v", got)
	}
}

func TestParseRedisInfoNewFields(t *testing.T) {
	info := "# Memory\r\nused_memory:1000\r\nmaxmemory:2000\r\nmaxmemory_policy:allkeys-lru\r\nmem_fragmentation_ratio:1.85\r\n" +
		"# Stats\r\nrejected_connections:3\r\n# Clients\r\nblocked_clients:2\r\n# Persistence\r\nrdb_last_bgsave_status:err\r\nslowlog_len:12\r\n"
	s := parseRedisInfo(info)
	if s.MaxmemoryPolicy != "allkeys-lru" || math.Abs(s.MemFragmentationRatio-1.85) > 0.001 {
		t.Fatalf("policy/frag wrong: %+v", s)
	}
	if s.RejectedConnections != 3 || s.BlockedClients != 2 || s.SlowlogLen != 12 {
		t.Fatalf("counters wrong: %+v", s)
	}
	if s.RdbLastBgsaveOK == nil || *s.RdbLastBgsaveOK {
		t.Fatalf("bgsave status should be false: %v", s.RdbLastBgsaveOK)
	}
	if parseRedisInfo("used_memory:1\r\n").RdbLastBgsaveOK != nil {
		t.Fatal("absent bgsave status must stay nil")
	}
}

func TestParseRedisSlowlog(t *testing.T) {
	out := `1) 1) (integer) 14
   2) (integer) 1309448221
   3) (integer) 15000
   4) 1) "keys"
      2) "user:secret:*"
   5) "127.0.0.1:58217"
   6) ""
2) 1) (integer) 13
   2) (integer) 1309448128
   3) (integer) 30
   4) 1) "SET"
      2) "session:abc"
      3) "token123"
`
	e := parseRedisSlowlog(out)
	if len(e) != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", len(e), e)
	}
	if e[0].Command != "KEYS" || e[0].Micros != 15000 || e[1].Command != "SET" || e[1].Micros != 30 {
		t.Fatalf("entries wrong: %+v", e)
	}
	for _, x := range e {
		if strings.Contains(x.Command, "secret") || strings.Contains(x.Command, "token") {
			t.Fatalf("argument leaked: %+v", x)
		}
	}
	if got := parseRedisSlowlog("(empty array)\n"); len(got) != 0 {
		t.Fatalf("empty slowlog: %+v", got)
	}
}

func TestParsePostgresFacts(t *testing.T) {
	out := "version\t16.3\nmax_connections\t100\nshared_buffers\t134217728\nwork_mem\t4194304\neffective_cache_size\t4294967296\n" +
		"uptime\t3600\nreplica\tf\nconnections\t85\nactive\t3\nidle_in_txn\t4\nlong_running\t1\nlongest\t42\n" +
		"blks_hit\t9000\nblks_read\t1000\ndeadlocks\t2\ntemp_bytes\t1048576\nxacts\t36000\nstats_age\t86400\n"
	st := parsePostgresFacts(out)
	if st.Version != "16.3" || st.MaxConnections != 100 || st.Connections != 85 || math.Abs(st.ConnUsagePct-85) > 0.001 {
		t.Fatalf("connection facts wrong: %+v", st)
	}
	if st.CacheHitPct == nil || math.Abs(*st.CacheHitPct-90) > 0.001 {
		t.Fatalf("cache hit = %v, want 90", st.CacheHitPct)
	}
	if st.CacheReads != 10000 {
		t.Fatalf("cache reads = %d, want 10000", st.CacheReads)
	}
	if st.IdleInTxn != 4 || st.LongRunningNum != 1 || st.LongestQuerySec != 42 || st.Deadlocks != 2 {
		t.Fatalf("activity facts wrong: %+v", st)
	}
	if st.SharedBuffersBytes != 134217728 || st.Replica || math.Abs(st.TxnPerSec-10) > 0.001 {
		t.Fatalf("config facts wrong: %+v", st)
	}
	if e := parsePostgresFacts("psql: error: connection refused"); e.Version != "" {
		t.Fatalf("error output should parse to no version: %+v", e)
	}
	if parsePostgresFacts("version\t15\nblks_hit\t0\nblks_read\t0\n").CacheHitPct != nil {
		t.Fatal("zero reads must keep cache hit nil")
	}
}

func TestParsePostgresQueryRows(t *testing.T) {
	lr := parsePostgresLongRunning("120\tactive\tSELECT * FROM invoices WHERE customer_email = 'x@y.z'\n")
	if len(lr) != 1 || lr[0].Seconds != 120 || strings.Contains(lr[0].Query, "x@y.z") {
		t.Fatalf("long running wrong: %+v", lr)
	}
	bl := parsePostgresBloat("public.events\t250000\t400000\t-1\npublic.logs\t20000\t50000\t7200\n")
	if len(bl) != 2 || bl[0].Table != "public.events" || bl[0].SinceVacuumS != -1 || bl[1].DeadTuples != 20000 {
		t.Fatalf("bloat wrong: %+v", bl)
	}
	ss := parsePostgresStatStatements("500\t250000\t3000\t50000\tSELECT * FROM orders WHERE id = $1\n0\t1\t1\t0\tbad\n")
	if len(ss) != 1 {
		t.Fatalf("want 1 pattern, got %+v", ss)
	}
	if ss[0].Count != 500 || math.Abs(ss[0].TotalSecs-250) > 0.001 || math.Abs(ss[0].AvgSeconds-0.5) > 0.001 || ss[0].MaxSeconds != 3 || ss[0].RowsExamAvg != 100 {
		t.Fatalf("stat statements math wrong: %+v", ss[0])
	}
}

func TestCollectPostgresPicksLargestDB(t *testing.T) {
	calls := map[string]string{}
	run := func(db, sql string) (string, error) {
		switch {
		case sql == pgFactsQuery:
			return "version\t16.3\nuptime\t10\n", nil
		case sql == pgLargestDBQuery:
			return "shop\n", nil
		case sql == pgStatStatementsPresentQuery:
			calls["present"] = db
			return "1\n", nil
		case sql == pgBloatQuery:
			calls["bloat"] = db
			return "public.events\t20000\t1000\t-1\n", nil
		case sql == pgStatStatementsQuery:
			calls["pgss"] = db
			return "10\t5000\t900\t100\tSELECT * FROM orders WHERE id = $1\n", nil
		}
		return "", nil
	}
	st, ok := collectPostgres(run, true)
	if !ok || st.Database != "shop" || !st.StatStatements {
		t.Fatalf("unexpected stat: ok=%v %+v", ok, st)
	}
	for _, k := range []string{"present", "bloat", "pgss"} {
		if calls[k] != "shop" {
			t.Fatalf("%s query ran against %q, want shop", k, calls[k])
		}
	}
	if len(st.TopSlow) != 1 || len(st.BloatedTables) != 1 {
		t.Fatalf("per-db facts missing: %+v", st)
	}
	// Without pickDB the default connection is used and Database stays empty.
	st2, _ := collectPostgres(run, false)
	if st2.Database != "" || calls["bloat"] != "" {
		t.Fatalf("pickDB=false should not switch databases: %+v", st2)
	}
}
