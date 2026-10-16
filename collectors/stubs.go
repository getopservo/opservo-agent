package collectors

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// Per-process CPU is measured over the interval BETWEEN heartbeats (like the
// system metric) and normalized to total capacity, so a single process is
// comparable to — and never exceeds — the overall cpu_percent. gopsutil's
// Process.CPUPercent is a LIFETIME average on a single-core basis (can exceed
// 100%), which made a short burst process (e.g. `apt`) look busier than the
// whole machine. We keep a small PID→cpu-seconds baseline between collections.
type procCPUSample struct {
	cpuSeconds float64
	at         time.Time
}

var (
	procCPUMu   sync.Mutex
	procCPUPrev = map[int32]procCPUSample{}
)

// maxProcesses bounds the heartbeat payload: we ship the top consumers by CPU
// then memory, which is what "what's using my server" needs anyway.
const maxProcesses = 40

// protoName maps a socket type (SOCK_STREAM/SOCK_DGRAM) to a protocol label.
func protoName(sockType uint32) string {
	switch sockType {
	case syscall.SOCK_STREAM:
		return "tcp"
	case syscall.SOCK_DGRAM:
		return "udp"
	default:
		return "unknown"
	}
}

// ── Process Collector ─────────────────────────────────────────────────────

type ProcessInfo struct {
	PID     int32   `json:"pid"`
	Name    string  `json:"name"`
	CPU     float64 `json:"cpu_percent"`
	MemMB   float32 `json:"mem_mb"`
	Status  string  `json:"status"`
	CmdLine string  `json:"cmdline"`
}

type ProcessCollector struct{}

func NewProcessCollector() *ProcessCollector { return &ProcessCollector{} }
func (p *ProcessCollector) Name() string     { return "processes" }

func (p *ProcessCollector) Collect(ctx context.Context) (interface{}, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	numCPU := float64(runtime.NumCPU())
	if numCPU < 1 {
		numCPU = 1
	}
	seen := make(map[int32]struct{}, len(procs))

	var result []ProcessInfo
	for _, proc := range procs {
		name, _ := proc.NameWithContext(ctx)
		// CPU% over the inter-heartbeat interval, as a share of TOTAL capacity.
		var cpuPct float64
		if times, e := proc.TimesWithContext(ctx); e == nil && times != nil {
			cpuSec := times.User + times.System
			procCPUMu.Lock()
			prev, ok := procCPUPrev[proc.Pid]
			procCPUPrev[proc.Pid] = procCPUSample{cpuSeconds: cpuSec, at: now}
			procCPUMu.Unlock()
			seen[proc.Pid] = struct{}{}
			if ok {
				if dt := now.Sub(prev.at).Seconds(); dt > 0 {
					cpuPct = (cpuSec - prev.cpuSeconds) / dt / numCPU * 100
					if cpuPct < 0 {
						cpuPct = 0
					}
				}
			} else if lp, e2 := proc.CPUPercentWithContext(ctx); e2 == nil {
				// First time seeing this PID — no interval yet. Use the lifetime
				// average, normalized to total capacity so it stays comparable.
				cpuPct = lp / numCPU
			}
		}
		memInfo, _ := proc.MemoryInfoWithContext(ctx)
		statuses, _ := proc.StatusWithContext(ctx)
		cmdline, _ := proc.CmdlineWithContext(ctx)

		var memMB float32
		if memInfo != nil {
			memMB = float32(memInfo.RSS) / 1024 / 1024
		}
		status := "unknown"
		if len(statuses) > 0 {
			status = statuses[0]
		}

		result = append(result, ProcessInfo{
			PID:     proc.Pid,
			Name:    name,
			CPU:     cpuPct,
			MemMB:   memMB,
			Status:  status,
			CmdLine: RedactSecrets(cmdline), // `mysql -pHunter2`, `--token …` are visible in ps to anyone; not to the cloud
		})
	}

	// Drop baseline entries for PIDs that have exited, so the map stays bounded.
	procCPUMu.Lock()
	for pid := range procCPUPrev {
		if _, ok := seen[pid]; !ok {
			delete(procCPUPrev, pid)
		}
	}
	procCPUMu.Unlock()

	// Keep the top consumers (CPU first, then memory) to bound the payload.
	sort.Slice(result, func(i, j int) bool {
		if result[i].CPU != result[j].CPU {
			return result[i].CPU > result[j].CPU
		}
		return result[i].MemMB > result[j].MemMB
	})
	if len(result) > maxProcesses {
		result = result[:maxProcesses]
	}
	return result, nil
}

// nonHTTPPorts are well-known ports we never send an HTTP GET to (databases,
// SSH, DNS, mail, …) — probing them is pointless and impolite.
var nonHTTPPorts = map[uint32]bool{
	22: true, 25: true, 53: true, 110: true, 143: true, 123: true, 111: true,
	137: true, 139: true, 445: true, 465: true, 587: true, 993: true, 995: true,
	2049: true, 3306: true, 5432: true, 6379: true, 5672: true, 9092: true,
	11211: true, 27017: true,
}

// probeHTTPStatuses best-effort GETs each plausibly-HTTP listening port on
// loopback and returns port→response-status, so the dashboard can tell a server
// that is actually serving (200/3xx) from one that is listening but broken
// (502) or not HTTP at all (absent). Read-only: a single GET with a short
// timeout, redirects not followed. Ports it can't reach are simply absent from
// the map.
func probeHTTPStatuses(ports []ListeningPort) map[uint32]int {
	// This now runs OFF the heartbeat path, but stay bounded anyway so a probe
	// goroutine can't be pinned open: 1s per probe, ≤4 in flight, 3s overall
	// budget (a host with many ports or a DROP-ing firewall can't hang it).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := &http.Client{
		Timeout:       1 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	out := make(map[uint32]int)
	var mu sync.Mutex
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i := range ports {
		if ports[i].Protocol != "tcp" || nonHTTPPorts[ports[i].Port] {
			continue
		}
		wg.Add(1)
		go func(port uint32) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return // overall probe budget exhausted — skip this port
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", port), nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "infrapilot-agent/health")
			resp, err := client.Do(req)
			if err != nil {
				return // connection refused / not HTTP / timeout → no entry
			}
			resp.Body.Close()
			mu.Lock()
			out[port] = resp.StatusCode
			mu.Unlock()
		}(ports[i].Port)
	}
	wg.Wait()
	return out
}

// HTTP reachability is probed OFF the heartbeat path. The collector
// serves the LAST completed probe's results from this cache and kicks a fresh
// probe in the background for the NEXT heartbeat, so probe latency never gates
// the current one. At most one probe runs at a time.
var (
	httpStatusMu     sync.Mutex
	httpStatusCache  = map[uint32]int{}
	httpProbeRunning bool
)

// applyCachedHTTPStatus fills each port's HTTPStatus from the last completed
// probe (ports absent from the cache keep status 0 — "unknown / not yet probed").
func applyCachedHTTPStatus(ports []ListeningPort) {
	httpStatusMu.Lock()
	defer httpStatusMu.Unlock()
	for i := range ports {
		if s, ok := httpStatusCache[ports[i].Port]; ok {
			ports[i].HTTPStatus = s
		}
	}
}

// refreshHTTPStatusInBackground probes the current ports in a background
// goroutine (single-flight) and replaces the cache for the next heartbeat.
// Replacing the whole map drops ports that are no longer listening.
func refreshHTTPStatusInBackground(ports []ListeningPort) {
	httpStatusMu.Lock()
	if httpProbeRunning {
		httpStatusMu.Unlock()
		return // a probe is still in flight — don't pile up
	}
	httpProbeRunning = true
	httpStatusMu.Unlock()

	targets := make([]ListeningPort, len(ports))
	copy(targets, ports) // the caller's slice is serialized into the heartbeat; don't share it
	go func() {
		defer func() {
			httpStatusMu.Lock()
			httpProbeRunning = false
			httpStatusMu.Unlock()
		}()
		fresh := probeHTTPStatuses(targets)
		httpStatusMu.Lock()
		httpStatusCache = fresh
		httpStatusMu.Unlock()
	}()
}

// ── Network Collector ─────────────────────────────────────────────────────

type ListeningPort struct {
	Port     uint32 `json:"port"`
	Protocol string `json:"protocol"`          // tcp | udp
	Address  string `json:"address,omitempty"` // bind address: 127.0.0.1 (local) vs 0.0.0.0 (exposed)
	PID      int32  `json:"pid,omitempty"`
	Process  string `json:"process,omitempty"`
	// Best-effort owning-process detail so the dashboard can recognise a dev/app
	// server behind the port (e.g. Vite on :5173) and name it from its project
	// dir. There are few listening ports, so the extra /proc reads are cheap.
	Cmdline    string   `json:"cmdline,omitempty"`     // full argv, space-joined (truncated)
	Cwd        string   `json:"cwd,omitempty"`         // working dir → project name
	Git        *GitInfo `json:"git,omitempty"`         // repo the dev server runs from (branch/commit/remote)
	HTTPStatus int      `json:"http_status,omitempty"` // GET / status on loopback: 200 serving, 502 listening-but-broken, 0 = not HTTP
}

type NetworkInfo struct {
	ListeningPorts []ListeningPort `json:"listening_ports"`
	// Cumulative bytes since boot (all interfaces). The dashboard derives the
	// up/down rate from the delta between consecutive heartbeats, so the agent
	// adds no sampling latency here.
	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
	// Network-health facts for OHS (nil when the probe couldn't run → dormant).
	NICDown          *bool    `json:"nic_down,omitempty"`
	GatewayReachable *bool    `json:"gateway_reachable,omitempty"`
	PacketLossPct    *float64 `json:"packet_loss_percent,omitempty"`
	DNSResolves      *bool    `json:"dns_resolves,omitempty"`
	InterfaceErrors  *int     `json:"interface_errors,omitempty"` // rx+tx errs+drops on the primary NIC since the last heartbeat
	// TCPRetransmitPct: retransmitted TCP segments as a % of segments sent over
	// the interval — a link-quality / congestion signal ahead of visible loss.
	TCPRetransmitPct *float64 `json:"tcp_retransmit_percent,omitempty"`
	// TCPOutSegments: segments sent over the same interval, so the API can
	// refuse to judge a retransmit % computed over a trickle of traffic.
	TCPOutSegments *uint64 `json:"tcp_out_segments,omitempty"`
	// ConntrackPct: nf_conntrack table utilization (%); at ~100% new connections
	// are silently dropped. nil when conntrack isn't loaded.
	ConntrackPct *float64 `json:"conntrack_percent,omitempty"`
	// ListenOverflows: accept-queue (SYN backlog) overflows over the interval —
	// a service can't accept connections fast enough.
	ListenOverflows *int      `json:"listen_overflows,omitempty"`
	CollectedAt     time.Time `json:"collected_at"`
}

type NetworkCollector struct{}

func NewNetworkCollector() *NetworkCollector { return &NetworkCollector{} }
func (n *NetworkCollector) Name() string     { return "network" }

func (n *NetworkCollector) Collect(ctx context.Context) (interface{}, error) {
	conns, err := net.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil, err
	}

	seen := make(map[uint32]bool)
	var ports []ListeningPort
	for _, c := range conns {
		if c.Status != "LISTEN" || seen[c.Laddr.Port] {
			continue
		}
		seen[c.Laddr.Port] = true
		lp := ListeningPort{
			Port:     c.Laddr.Port,
			Protocol: protoName(c.Type),
			Address:  c.Laddr.IP,
			PID:      c.Pid,
		}
		// Resolve the owning process (best-effort; there are few ports). We grab
		// the name plus the cmdline + cwd so the dashboard can classify a dev/app
		// server (Vite/Next/Django/…) and name it from its project directory.
		if c.Pid > 0 {
			if p, err := process.NewProcessWithContext(ctx, c.Pid); err == nil {
				if n, err := p.NameWithContext(ctx); err == nil {
					lp.Process = n
				}
				if cmd, err := p.CmdlineWithContext(ctx); err == nil && cmd != "" {
					if len(cmd) > 512 {
						cmd = cmd[:512]
					}
					lp.Cmdline = RedactSecrets(cmd)
				}
				if cwd, err := p.CwdWithContext(ctx); err == nil {
					lp.Cwd = cwd
					// Link the repo the dev server runs from, when its cwd is one.
					if git, ok := readGitInfo(ctx, cwd); ok {
						lp.Git = git
					}
				}
			}
		}
		ports = append(ports, lp)
	}

	// Reachability: serve the previous probe's cached results and kick a fresh
	// probe in the background, so HTTP probing never gates this heartbeat.
	applyCachedHTTPStatus(ports)
	refreshHTTPStatusInBackground(ports)

	info := &NetworkInfo{
		ListeningPorts: ports,
		CollectedAt:    time.Now().UTC(),
	}
	// Aggregate traffic counters across all interfaces.
	if io, err := net.IOCountersWithContext(ctx, false); err == nil && len(io) > 0 {
		info.BytesSent = io[0].BytesSent
		info.BytesRecv = io[0].BytesRecv
	}
	// Reachability / loss / DNS / NIC state (see nethealth.go).
	fillNetworkHealth(ctx, info)
	return info, nil
}
