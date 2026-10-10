package collectors

import (
	"strconv"
	"testing"
)

func TestParsePSISome(t *testing.T) {
	psi := "some avg10=12.34 avg60=5.00 avg300=1.20 total=999\n" +
		"full avg10=8.00 avg60=2.00 avg300=0.50 total=500\n"
	v, ok := parsePSISome(psi)
	if !ok || v != 12.34 {
		t.Fatalf("parsePSISome = %v, %v; want 12.34, true", v, ok)
	}
	if _, ok := parsePSISome("garbage"); ok {
		t.Fatal("expected ok=false for garbage")
	}
}

func TestParsePSISomeAvg300(t *testing.T) {
	psi := "some avg10=12.34 avg60=5.00 avg300=1.20 total=999\n" +
		"full avg10=8.00 avg60=2.00 avg300=0.50 total=500\n"
	if v, ok := parsePSISomeAvg(psi, "avg300"); !ok || v != 1.20 {
		t.Fatalf("avg300 = %v, %v; want 1.20 (the \"some\" line, not \"full\")", v, ok)
	}
	if _, ok := parsePSISomeAvg(psi, "avg900"); ok {
		t.Fatal("unknown key must not parse")
	}
}

func TestParseDefaultRoute(t *testing.T) {
	// eth0 default route via 192.168.0.1 (gateway hex LE = 0100A8C0).
	route := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n" +
		"eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
	iface, gw, ok := parseDefaultRoute(route)
	if !ok || iface != "eth0" || gw != "192.168.0.1" {
		t.Fatalf("parseDefaultRoute = %q %q %v; want eth0 192.168.0.1 true", iface, gw, ok)
	}
	if _, _, ok := parseDefaultRoute("no default route here\n"); ok {
		t.Fatal("expected ok=false when no default route")
	}
}

func TestHexLEToIP(t *testing.T) {
	ip, err := hexLEToIP("0100A8C0")
	if err != nil || ip != "192.168.0.1" {
		t.Fatalf("hexLEToIP = %q, %v; want 192.168.0.1", ip, err)
	}
}

func TestParsePingLoss(t *testing.T) {
	out := "PING 1.1.1.1 56 data bytes\n--- 1.1.1.1 ping statistics ---\n" +
		"3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
	if v, ok := parsePingLoss(out); !ok || v != 0 {
		t.Fatalf("parsePingLoss = %v %v; want 0 true", v, ok)
	}
	lossy := "5 packets transmitted, 3 received, 40% packet loss, time 4008ms\n"
	if v, ok := parsePingLoss(lossy); !ok || v != 40 {
		t.Fatalf("parsePingLoss = %v %v; want 40 true", v, ok)
	}
	if _, ok := parsePingLoss("no stats"); ok {
		t.Fatal("expected ok=false")
	}
}

func TestParseInterfaceErrors(t *testing.T) {
	dev := "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"  eth0: 1000000  5000    3    2    0    0     0          0        900000   4000    1    4    0    0     0       0\n" +
		"    lo:  500      5       0    0    0    0     0          0        500      5       0    0    0    0     0       0\n"
	// eth0: rx errs 3 + rx drop 2 + tx errs 1 + tx drop 4 = 10
	if n := parseInterfaceErrors(dev, "eth0"); n != 10 {
		t.Fatalf("parseInterfaceErrors(eth0) = %d; want 10", n)
	}
	if n := parseInterfaceErrors(dev, "lo"); n != 0 {
		t.Fatalf("parseInterfaceErrors(lo) = %d; want 0", n)
	}
	if n := parseInterfaceErrors(dev, "wlan0"); n != 0 {
		t.Fatalf("missing iface should be 0, got %d", n)
	}
}

func TestParseCtxt(t *testing.T) {
	stat := "cpu  1 2 3 4\nintr 100\nctxt 123456789\nbtime 111\n"
	if v, ok := parseCtxt(stat); !ok || v != 123456789 {
		t.Fatalf("parseCtxt = %d %v; want 123456789 true", v, ok)
	}
	if _, ok := parseCtxt("no ctxt line"); ok {
		t.Fatal("expected ok=false")
	}
}

func TestParseCgroupCPUStat(t *testing.T) {
	stat := "usage_usec 1000\nnr_periods 500\nnr_throttled 12\nthrottled_usec 3400\n"
	p, thr, ok := parseCgroupCPUStat(stat)
	if !ok || p != 500 || thr != 12 {
		t.Fatalf("parseCgroupCPUStat = %d %d %v; want 500 12 true", p, thr, ok)
	}
	if _, _, ok := parseCgroupCPUStat("usage_usec 1000\n"); ok {
		t.Fatal("expected ok=false without period/throttle lines")
	}
}

func TestParseFileNr(t *testing.T) {
	if p, ok := parseFileNr("8192 0 100000\n"); !ok || p < 8.19 || p > 8.20 {
		t.Fatalf("parseFileNr = %v %v; want ~8.19 true", p, ok)
	}
	if _, ok := parseFileNr("bad"); ok {
		t.Fatal("expected ok=false")
	}
}

func TestDiskAwait(t *testing.T) {
	// Only whole disks (sda, nvme0n1) parsed; partitions (sda1) skipped.
	stat := func(readsMs, reads, writesMs, writes uint64) string {
		return "   8       0 sda " +
			strconv.FormatUint(reads, 10) + " 0 0 " + strconv.FormatUint(readsMs, 10) + " " +
			strconv.FormatUint(writes, 10) + " 0 0 " + strconv.FormatUint(writesMs, 10) + " 0 0 0\n" +
			"   8       1 sda1 5 0 0 5 5 0 0 5 0 0 0\n"
	}
	prev := parseDiskStats(stat(1000, 100, 1000, 100)) // 200 ops, 2000ms cumulative
	cur := parseDiskStats(stat(3000, 150, 3000, 150))  // +100 ops, +4000ms → await 40ms
	if _, has := prev["sda1"]; has {
		t.Fatal("partitions should be skipped")
	}
	if await, ok := worstDiskAwait(prev, cur); !ok || await != 40 {
		t.Fatalf("worstDiskAwait = %v %v; want 40 true", await, ok)
	}
	// The sample size behind the average is reported alongside it.
	if await, ops, ok := worstDiskAwaitOps(prev, cur); !ok || await != 40 || ops != 100 {
		t.Fatalf("worstDiskAwaitOps = %v %v %v; want 40 100 true", await, ops, ok)
	}
	// First sample (no prev) → not available.
	if _, ok := worstDiskAwait(nil, cur); ok {
		t.Fatal("expected ok=false on first sample")
	}
	// Too few ops → ignored.
	small := parseDiskStats(stat(1005, 102, 1005, 102))
	if _, ok := worstDiskAwait(prev, small); ok {
		t.Fatal("expected ok=false for <10 ops")
	}
}

func TestParseProcsBlocked(t *testing.T) {
	stat := "cpu 1 2 3\nctxt 100\nprocs_running 3\nprocs_blocked 7\n"
	if b, ok := parseProcsBlocked(stat); !ok || b != 7 {
		t.Fatalf("parseProcsBlocked = %d %v; want 7 true", b, ok)
	}
	if _, ok := parseProcsBlocked("no such line"); ok {
		t.Fatal("expected ok=false")
	}
}

func TestParseNTPSynchronized(t *testing.T) {
	if !parseNTPSynchronized("yes\n") {
		t.Fatal("want true for yes")
	}
	if parseNTPSynchronized("no\n") {
		t.Fatal("want false for no")
	}
}

func TestParseSwapTotal(t *testing.T) {
	mi := "MemTotal:       16384000 kB\nSwapTotal:       2097148 kB\nSwapFree: 2097148 kB\n"
	if n := parseSwapTotal(mi); n != 2097148 {
		t.Fatalf("parseSwapTotal = %d; want 2097148", n)
	}
	if n := parseSwapTotal("MemTotal: 100 kB\nSwapTotal:       0 kB\n"); n != 0 {
		t.Fatalf("parseSwapTotal = %d; want 0", n)
	}
}

func TestParseDpkgAudit(t *testing.T) {
	if n := parseDpkgAudit(""); n != 0 {
		t.Fatalf("clean audit = %d; want 0", n)
	}
	audit := "The following packages are in a mess due to serious problems:\n" +
		" libfoo\n somepkg\n"
	if n := parseDpkgAudit(audit); n != 2 {
		t.Fatalf("parseDpkgAudit = %d; want 2", n)
	}
}

func TestParseAutoremoveCount(t *testing.T) {
	out := "Reading package lists...\n0 upgraded, 0 newly installed, 4 to remove and 0 not upgraded.\n"
	if n := parseAutoremoveCount(out); n != 4 {
		t.Fatalf("parseAutoremoveCount = %d; want 4", n)
	}
	if n := parseAutoremoveCount("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"); n != 0 {
		t.Fatalf("parseAutoremoveCount = %d; want 0", n)
	}
}

func TestRetransmitDelta(t *testing.T) {
	pct, segs, ok := retransmitDelta(1000, 10, 21000, 410)
	if !ok || segs != 20000 || pct != 2 {
		t.Fatalf("retransmitDelta = %v %v %v; want 2 20000 true", pct, segs, ok)
	}
	// Nothing sent (or counter reset) → no reading at all, not 0%.
	if _, _, ok := retransmitDelta(500, 5, 500, 9); ok {
		t.Fatal("expected ok=false when no segments were sent")
	}
	// Retransmit counter going backwards is clamped to 0, not a wrap-around.
	if pct, _, ok := retransmitDelta(0, 50, 100, 10); !ok || pct != 0 {
		t.Fatalf("pct = %v %v; want 0 true", pct, ok)
	}
}
