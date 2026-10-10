package collectors

import (
	"math"
	"testing"
)

func TestParseMySQLStatus(t *testing.T) {
	out := "Threads_connected\t20\n" +
		"Threads_running\t3\n" +
		"Questions\t360000\n" +
		"Slow_queries\t15\n" +
		"Aborted_connects\t4\n" +
		"Uptime\t3600\n" +
		"max_connections\t100\n" +
		"8.0.36\n"
	s, _ := parseMySQLStatus(out)
	if s.ThreadsConnected != 20 || s.MaxConnections != 100 {
		t.Fatalf("conn fields wrong: %+v", s)
	}
	if math.Abs(s.ConnUsagePct-20) > 0.001 { // 20/100
		t.Fatalf("conn usage = %f, want 20", s.ConnUsagePct)
	}
	if math.Abs(s.QueriesPerSec-100) > 0.001 { // 360000/3600
		t.Fatalf("qps = %f, want 100", s.QueriesPerSec)
	}
	if s.SlowQueries != 15 || s.Version != "8.0.36" || s.UptimeSeconds != 3600 {
		t.Fatalf("misc fields wrong: %+v", s)
	}
}

func TestParseMySQLStatusEmpty(t *testing.T) {
	if s, _ := parseMySQLStatus("ERROR 1045 (28000): Access denied"); s.UptimeSeconds != 0 {
		t.Fatalf("error output should parse to zero uptime, got %+v", s)
	}
}
