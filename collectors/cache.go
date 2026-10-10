package collectors

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Per-heartbeat command de-duplication. Several collectors run
// concurrently and independently, and a few need the SAME expensive command in
// the same cycle — `docker stats` (services + containers) and `apt list
// --upgradable` (updates + packages). cachedCmd runs such a command at most once
// per ttl and is singleflight: a concurrent second caller blocks until the first
// finishes, then reuses its result, so only ONE subprocess is spawned per cycle.

type cmdResult struct {
	out []byte
	err error
	at  time.Time
}

var (
	cmdCacheMu sync.Mutex
	cmdCache   = map[string]cmdResult{}
	cmdKeyLock = map[string]*sync.Mutex{}
)

func cachedCmd(ctx context.Context, ttl, timeout time.Duration, name string, args ...string) ([]byte, error) {
	key := name + "\x00" + strings.Join(args, "\x00")

	cmdCacheMu.Lock()
	if r, ok := cmdCache[key]; ok && time.Since(r.at) < ttl {
		cmdCacheMu.Unlock()
		return r.out, r.err
	}
	lk, ok := cmdKeyLock[key]
	if !ok {
		lk = &sync.Mutex{}
		cmdKeyLock[key] = lk
	}
	cmdCacheMu.Unlock()

	// Serialize callers of the SAME command so only one runs it; others wait here
	// and then read the cache below.
	lk.Lock()
	defer lk.Unlock()

	cmdCacheMu.Lock()
	if r, ok := cmdCache[key]; ok && time.Since(r.at) < ttl {
		cmdCacheMu.Unlock()
		return r.out, r.err
	}
	cmdCacheMu.Unlock()

	out, err := runCmdTimeout(ctx, timeout, name, args...)

	cmdCacheMu.Lock()
	cmdCache[key] = cmdResult{out: out, err: err, at: time.Now()}
	cmdCacheMu.Unlock()
	return out, err
}

// sharedDockerStats runs one `docker stats --no-stream` for the heartbeat and
// returns raw tab-separated rows: Name\tCPU%\tMemUsage\tMem%\tNetIO. Both the
// services and containers collectors read from this single call. The
// 30s TTL (< the 60s heartbeat) means it refreshes each cycle but dedups within one.
func sharedDockerStats(ctx context.Context) ([]byte, error) {
	return cachedCmd(ctx, 30*time.Second, 8*time.Second,
		"docker", "stats", "--no-stream", "--no-trunc",
		"--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}")
}

// sharedAptUpgradable runs one `apt list --upgradable` for the heartbeat, shared
// by the updates and packages collectors.
func sharedAptUpgradable(ctx context.Context) ([]byte, error) {
	return cachedCmd(ctx, 30*time.Second, 10*time.Second, "sh", "-c", "apt list --upgradable 2>/dev/null")
}
