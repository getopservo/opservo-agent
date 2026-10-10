package collectors

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RedisStat is one Redis instance's key health metrics (from `redis-cli INFO`).
type RedisStat struct {
	Name             string  `json:"name"`   // container name, or "localhost"
	Source           string  `json:"source"` // host | container
	UsedMemoryBytes  int64   `json:"used_memory_bytes"`
	MaxMemoryBytes   int64   `json:"maxmemory_bytes"`
	ConnectedClients int     `json:"connected_clients"`
	OpsPerSec        int     `json:"ops_per_sec"`
	HitRate          float64 `json:"hit_rate"` // keyspace hits/(hits+misses) %
	// KeyspaceLookups = hits+misses since start: the sample size behind
	// HitRate (which reads 0 when there were no lookups at all).
	KeyspaceLookups *int64 `json:"keyspace_lookups,omitempty"`
	Keys            int    `json:"keys"` // total across DBs
	EvictedKeys     int64  `json:"evicted_keys"`
	ExpiredKeys     int64  `json:"expired_keys"`
	Role            string `json:"role"`
	UptimeSeconds   int64  `json:"uptime_seconds"`

	// ── Configuration + pressure facts (database insights) ───────────
	MaxmemoryPolicy       string  `json:"maxmemory_policy,omitempty"`
	MemFragmentationRatio float64 `json:"mem_fragmentation_ratio,omitempty"`
	RejectedConnections   int64   `json:"rejected_connections"` // cumulative: clients turned away at maxclients
	BlockedClients        int     `json:"blocked_clients"`
	RdbLastBgsaveOK       *bool   `json:"rdb_last_bgsave_ok,omitempty"`
	SlowlogLen            int     `json:"slowlog_len"`
	// Recent SLOWLOG entries: command NAME + duration only, arguments (keys,
	// values) are never shipped.
	SlowCommands []RedisSlowEntry `json:"slow_commands,omitempty"`
}

// RedisSlowEntry is one `SLOWLOG GET` entry reduced to its command name.
type RedisSlowEntry struct {
	Command string `json:"command"`
	Micros  int64  `json:"micros"`
}

// RedisInfo: per-instance Redis metrics. No credentials configured — best-effort:
// works when INFO is allowed without auth (local or container exec).
type RedisInfo struct {
	Available bool        `json:"available"`
	Instances []RedisStat `json:"instances"`
}

type RedisCollector struct{}

func NewRedisCollector() *RedisCollector { return &RedisCollector{} }
func (r *RedisCollector) Name() string   { return "redis" }

var redisContainerRe = regexp.MustCompile(`(?i)redis|valkey`)

func (r *RedisCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &RedisInfo{Instances: []RedisStat{}}

	// 1. Local redis (host install or a port published to localhost).
	if hasBinary("redis-cli") {
		if out, err := runCmdTimeout(ctx, 4*time.Second, "redis-cli", "INFO"); err == nil && len(out) > 0 {
			st := parseRedisInfo(string(out))
			if st.UptimeSeconds > 0 || st.UsedMemoryBytes > 0 {
				st.Name, st.Source = "localhost", "host"
				if sl, err := runCmdTimeout(ctx, 4*time.Second, "redis-cli", "SLOWLOG", "GET", "10"); err == nil {
					st.SlowCommands = parseRedisSlowlog(string(sl))
				}
				info.Available = true
				info.Instances = append(info.Instances, st)
			}
		}
	}

	// 2. Containerized redis (exec redis-cli inside each redis container). Covers
	//    the common case where redis runs in Docker with no published port.
	for _, c := range listContainers(ctx) {
		if !redisContainerRe.MatchString(c.Name) && !redisContainerRe.MatchString(c.Image) {
			continue
		}
		out, err := runCmdTimeout(ctx, 5*time.Second, "docker", "exec", c.Name, "redis-cli", "INFO")
		if err != nil || len(out) == 0 {
			continue // password-protected or non-redis — skip quietly
		}
		st := parseRedisInfo(string(out))
		if st.UptimeSeconds == 0 && st.UsedMemoryBytes == 0 {
			continue
		}
		st.Name, st.Source = c.Name, "container"
		if sl, err := runCmdTimeout(ctx, 4*time.Second, "docker", "exec", c.Name, "redis-cli", "SLOWLOG", "GET", "10"); err == nil {
			st.SlowCommands = parseRedisSlowlog(string(sl))
		}
		info.Available = true
		info.Instances = append(info.Instances, st)
	}

	return info, nil
}

var redisDbKeysRe = regexp.MustCompile(`keys=(\d+)`)

// parseRedisInfo parses `redis-cli INFO` (key:value lines, db sections). Pure + tested.
func parseRedisInfo(out string) RedisStat {
	var s RedisStat
	var hits, misses float64
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch k {
		case "used_memory":
			s.UsedMemoryBytes, _ = strconv.ParseInt(v, 10, 64)
		case "maxmemory":
			s.MaxMemoryBytes, _ = strconv.ParseInt(v, 10, 64)
		case "connected_clients":
			s.ConnectedClients, _ = strconv.Atoi(v)
		case "instantaneous_ops_per_sec":
			s.OpsPerSec, _ = strconv.Atoi(v)
		case "keyspace_hits":
			hits, _ = strconv.ParseFloat(v, 64)
		case "keyspace_misses":
			misses, _ = strconv.ParseFloat(v, 64)
		case "evicted_keys":
			s.EvictedKeys, _ = strconv.ParseInt(v, 10, 64)
		case "expired_keys":
			s.ExpiredKeys, _ = strconv.ParseInt(v, 10, 64)
		case "role":
			s.Role = v
		case "maxmemory_policy":
			s.MaxmemoryPolicy = v
		case "mem_fragmentation_ratio":
			s.MemFragmentationRatio, _ = strconv.ParseFloat(v, 64)
		case "rejected_connections":
			s.RejectedConnections, _ = strconv.ParseInt(v, 10, 64)
		case "blocked_clients":
			s.BlockedClients, _ = strconv.Atoi(v)
		case "slowlog_len":
			s.SlowlogLen, _ = strconv.Atoi(v)
		case "rdb_last_bgsave_status":
			ok := v == "ok"
			s.RdbLastBgsaveOK = &ok
		case "uptime_in_seconds":
			s.UptimeSeconds, _ = strconv.ParseInt(v, 10, 64)
		default:
			if strings.HasPrefix(k, "db") { // db0:keys=42,expires=1,...
				if m := redisDbKeysRe.FindStringSubmatch(v); m != nil {
					n, _ := strconv.Atoi(m[1])
					s.Keys += n
				}
			}
		}
	}
	if hits+misses > 0 {
		s.HitRate = hits / (hits + misses) * 100
	}
	lookups := int64(hits + misses)
	s.KeyspaceLookups = &lookups
	return s
}

var (
	redisSlowEntryRe = regexp.MustCompile(`^\s*\d+\)\s+1\)\s+\(integer\)`)
	redisIntRe       = regexp.MustCompile(`\(integer\)\s+(-?\d+)`)
	redisStrRe       = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
)

// parseRedisSlowlog reduces `redis-cli SLOWLOG GET n` (non-tty output) to
// command name + duration per entry. Each entry looks like:
//
//  1. 1) (integer) 14          ← id
//  2. (integer) 1309448221  ← unix time
//  3. (integer) 15          ← duration (µs)
//  4. 1) "ping"             ← command + args (only the name is kept)
//  2. "..."
//  5. "127.0.0.1:58217"
//
// Pure + unit-tested.
func parseRedisSlowlog(out string) []RedisSlowEntry {
	var entries []RedisSlowEntry
	var cur *RedisSlowEntry
	ints := 0
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if redisSlowEntryRe.MatchString(line) {
			if cur != nil && cur.Command != "" {
				entries = append(entries, *cur)
			}
			cur = &RedisSlowEntry{}
			ints = 0
		}
		if cur == nil {
			continue
		}
		if cur.Command == "" {
			if m := redisIntRe.FindStringSubmatch(line); m != nil && ints < 3 {
				ints++
				if ints == 3 {
					cur.Micros, _ = strconv.ParseInt(m[1], 10, 64)
				}
				continue
			}
			if ints == 3 {
				if m := redisStrRe.FindStringSubmatch(line); m != nil {
					cur.Command = strings.ToUpper(m[1])
				}
			}
		}
	}
	if cur != nil && cur.Command != "" {
		entries = append(entries, *cur)
	}
	return entries
}
