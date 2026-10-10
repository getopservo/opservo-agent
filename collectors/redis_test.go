package collectors

import (
	"math"
	"testing"
)

func TestParseRedisInfo(t *testing.T) {
	info := `# Server
redis_version:7.2.0
uptime_in_seconds:3600
# Clients
connected_clients:5
# Memory
used_memory:1048576
maxmemory:0
# Stats
instantaneous_ops_per_sec:120
keyspace_hits:900
keyspace_misses:100
expired_keys:7
evicted_keys:2
# Replication
role:master
# Keyspace
db0:keys=42,expires=3,avg_ttl=0
db1:keys=8,expires=0,avg_ttl=0`
	s := parseRedisInfo(info)
	if s.UsedMemoryBytes != 1048576 || s.ConnectedClients != 5 || s.OpsPerSec != 120 {
		t.Fatalf("basic fields wrong: %+v", s)
	}
	if s.Keys != 50 { // 42 + 8
		t.Fatalf("keys = %d, want 50", s.Keys)
	}
	if math.Abs(s.HitRate-90) > 0.001 { // 900/1000
		t.Fatalf("hit rate = %f, want 90", s.HitRate)
	}
	if s.KeyspaceLookups == nil || *s.KeyspaceLookups != 1000 {
		t.Fatalf("keyspace lookups = %v, want 1000", s.KeyspaceLookups)
	}
	// No lookups at all: hit_rate stays 0 but the count says why (0 of 0, not a 0% cache).
	if idle := parseRedisInfo("keyspace_hits:0\nkeyspace_misses:0\n"); idle.KeyspaceLookups == nil || *idle.KeyspaceLookups != 0 || idle.HitRate != 0 {
		t.Fatalf("idle redis: %+v", idle)
	}
	if s.Role != "master" || s.UptimeSeconds != 3600 {
		t.Fatalf("role/uptime wrong: %+v", s)
	}
}

func TestParseRedisInfoEmpty(t *testing.T) {
	if s := parseRedisInfo("NOAUTH Authentication required."); s.UsedMemoryBytes != 0 || s.UptimeSeconds != 0 {
		t.Fatalf("auth-error output should parse to zero, got %+v", s)
	}
}
