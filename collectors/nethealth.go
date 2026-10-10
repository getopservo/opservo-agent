package collectors

import (
	"context"
	stdnet "net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Baseline of cumulative interface errors per NIC, so we report the delta since
// the last heartbeat (errors happening NOW) rather than a since-boot total that
// would flag long-healed blips forever.
var (
	ifErrMu   sync.Mutex
	ifErrPrev = map[string]uint64{}

	// Baselines for interval-delta TCP counters (retransmits, accept-queue
	// overflows). Reported only once a prior sample exists → rule dormant first tick.
	tcpCtrMu                     sync.Mutex
	prevOutSegs, prevRetransSegs uint64
	prevListenOverflows          uint64
	tcpCtrHad                    bool
)

// fillNetworkHealth populates the OHS network-health facts on a NetworkInfo:
// gateway reachability + packet loss (ping), DNS resolution, and whether the
// default-route interface is down. Every probe is best-effort — a field stays
// nil (→ its OHS rule dormant) when the probe can't run, never a false alarm.
func fillNetworkHealth(ctx context.Context, info *NetworkInfo) {
	iface, gw, ok := parseDefaultRoute(readProcFile("/proc/net/route"))

	// NIC state: only the DEFAULT-route interface (a VM has many down virtual
	// ifaces that are irrelevant). Down here means the box's primary link is gone.
	if ok && iface != "" {
		if state := strings.TrimSpace(readProcFile("/sys/class/net/" + iface + "/operstate")); state != "" {
			down := state == "down"
			info.NICDown = &down
		}
		// Interface errors as a per-interval delta (needs a prior sample).
		cur := parseInterfaceErrors(readProcFile("/proc/net/dev"), iface)
		ifErrMu.Lock()
		prev, had := ifErrPrev[iface]
		ifErrPrev[iface] = cur
		ifErrMu.Unlock()
		if had && cur >= prev {
			d := int(cur - prev)
			info.InterfaceErrors = &d
		}
	}

	// Gateway reachability + packet loss via ping (3 probes, 4s cap).
	if ok && gw != "" && hasBinary("ping") {
		if out, err := runCmdTimeout(ctx, 5*time.Second, "ping", "-c", "3", "-w", "4", gw); err == nil || len(out) > 0 {
			if loss, ok := parsePingLoss(string(out)); ok {
				info.PacketLossPct = &loss
				reachable := loss < 100
				info.GatewayReachable = &reachable
			}
		}
	}

	// DNS: resolve a stable public name through the system resolver, short timeout.
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var r stdnet.Resolver
	_, derr := r.LookupHost(dctx, "one.one.one.one")
	resolves := derr == nil
	info.DNSResolves = &resolves

	fillNetworkCounters(info)
}

// fillNetworkCounters adds TCP retransmit rate, conntrack-table utilization, and
// accept-queue overflow deltas from /proc. All best-effort → each field stays
// nil (its rule dormant) when the source is unavailable.
func fillNetworkCounters(info *NetworkInfo) {
	snmp := readProcFile("/proc/net/snmp")
	out, okO := procCounter(snmp, "Tcp:", "OutSegs")
	rt, okR := procCounter(snmp, "Tcp:", "RetransSegs")
	netstat := readProcFile("/proc/net/netstat")
	ov, okV := procCounter(netstat, "TcpExt:", "ListenOverflows")

	tcpCtrMu.Lock()
	pOut, pRt, pOv, had := prevOutSegs, prevRetransSegs, prevListenOverflows, tcpCtrHad
	if okO {
		prevOutSegs = out
	}
	if okR {
		prevRetransSegs = rt
	}
	if okV {
		prevListenOverflows = ov
	}
	tcpCtrHad = true
	tcpCtrMu.Unlock()

	if had && okO && okR {
		if pct, dOut, ok := retransmitDelta(pOut, pRt, out, rt); ok {
			info.TCPRetransmitPct = &pct
			info.TCPOutSegments = &dOut
		}
	}
	if had && okV && ov >= pOv {
		d := int(ov - pOv)
		info.ListenOverflows = &d
	}

	// Conntrack utilization is point-in-time (count vs max).
	cntS := strings.TrimSpace(readProcFile("/proc/sys/net/netfilter/nf_conntrack_count"))
	maxS := strings.TrimSpace(readProcFile("/proc/sys/net/netfilter/nf_conntrack_max"))
	if cntS != "" && maxS != "" {
		cnt, e1 := strconv.ParseFloat(cntS, 64)
		max, e2 := strconv.ParseFloat(maxS, 64)
		if e1 == nil && e2 == nil && max > 0 {
			pct := cnt / max * 100
			info.ConntrackPct = &pct
		}
	}
}

// retransmitDelta turns two cumulative (OutSegs, RetransSegs) samples into the
// interval's retransmit % and the number of segments sent — the sample size
// the API needs to tell a lossy link from three retransmits out of fifty.
// ok=false when nothing was sent (or the counters went backwards).
func retransmitDelta(prevOut, prevRt, out, rt uint64) (pct float64, dOut uint64, ok bool) {
	if out <= prevOut {
		return 0, 0, false
	}
	var dRt uint64
	if rt > prevRt {
		dRt = rt - prevRt
	}
	dOut = out - prevOut
	return float64(dRt) / float64(dOut) * 100, dOut, true
}

// procCounter reads a named counter from the two-line "Proto: names\nProto:
// values" format used by /proc/net/snmp and /proc/net/netstat.
func procCounter(text, prefix, key string) (uint64, bool) {
	var names, vals []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		// The header row has the metric NAMES; the values row is all numbers.
		if _, err := strconv.ParseUint(f[1], 10, 64); err != nil {
			names = f
		} else {
			vals = f
		}
	}
	if len(names) == 0 || len(vals) != len(names) {
		return 0, false
	}
	for i, n := range names {
		if n == key {
			v, err := strconv.ParseUint(vals[i], 10, 64)
			return v, err == nil
		}
	}
	return 0, false
}

func readProcFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// parseDefaultRoute returns the interface name and gateway IP of the default
// route from /proc/net/route. The gateway is stored as a little-endian hex
// integer. Pure and testable.
func parseDefaultRoute(procRoute string) (iface, gateway string, ok bool) {
	for _, line := range strings.Split(procRoute, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		// Columns: Iface Destination Gateway Flags ...
		if f[1] != "00000000" { // default route destination = 0.0.0.0
			continue
		}
		gw, err := hexLEToIP(f[2])
		if err != nil {
			continue
		}
		return f[0], gw, true
	}
	return "", "", false
}

// hexLEToIP converts a little-endian hex IPv4 (as in /proc/net/route) to dotted
// decimal, e.g. "0100A8C0" → "192.168.0.1".
func hexLEToIP(h string) (string, error) {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return "", err
	}
	b0 := v & 0xff
	b1 := (v >> 8) & 0xff
	b2 := (v >> 16) & 0xff
	b3 := (v >> 24) & 0xff
	return strconv.FormatUint(b0, 10) + "." + strconv.FormatUint(b1, 10) + "." +
		strconv.FormatUint(b2, 10) + "." + strconv.FormatUint(b3, 10), nil
}

// parseInterfaceErrors sums rx+tx errors and drops for one interface from
// /proc/net/dev. Columns after "iface:" are: rx[bytes packets errs drop fifo
// frame compressed multicast] tx[bytes packets errs drop ...]. Pure/testable.
func parseInterfaceErrors(procNetDev, iface string) uint64 {
	for _, line := range strings.Split(procNetDev, "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 || strings.TrimSpace(line[:colon]) != iface {
			continue
		}
		f := strings.Fields(line[colon+1:])
		if len(f) < 12 {
			return 0
		}
		var sum uint64
		for _, idx := range []int{2, 3, 10, 11} { // rx errs, rx drop, tx errs, tx drop
			if v, err := strconv.ParseUint(f[idx], 10, 64); err == nil {
				sum += v
			}
		}
		return sum
	}
	return 0
}

var pingLossRe = regexp.MustCompile(`([\d.]+)% packet loss`)

// parsePingLoss extracts the packet-loss percentage from ping(8) output.
func parsePingLoss(out string) (float64, bool) {
	m := pingLossRe.FindStringSubmatch(out)
	if len(m) < 2 {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
