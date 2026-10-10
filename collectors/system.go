package collectors

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

// SystemInfo holds all system-level metrics.
type SystemInfo struct {
	Hostname      string     `json:"hostname"`
	IPAddress     string     `json:"ip_address"`
	PublicIP      string     `json:"public_ip,omitempty"`         // cloud metadata (EC2/GCE) public IPv4; API falls back to the heartbeat source
	CloudResource string     `json:"cloud_resource_id,omitempty"` // billing-side id (EC2 instance id / Azure ARM id / GCE global_name) for cost attribution
	OS            string     `json:"os"`
	Platform      string     `json:"platform"`
	Kernel        string     `json:"kernel"`
	Arch          string     `json:"arch"`
	Uptime        uint64     `json:"uptime_seconds"`
	CPUPercent    float64    `json:"cpu_percent"`
	CPUCores      int        `json:"cpu_cores"`
	CPUModel      string     `json:"cpu_model,omitempty"`
	CPUMhz        float64    `json:"cpu_mhz,omitempty"`
	MemTotal      uint64     `json:"mem_total_bytes"`
	MemUsed       uint64     `json:"mem_used_bytes"`
	MemPercent    float64    `json:"mem_percent"`
	MemAvailable  uint64     `json:"mem_available_bytes"`
	SwapTotal     uint64     `json:"swap_total_bytes"`
	SwapUsed      uint64     `json:"swap_used_bytes"`
	CPUSteal      float64    `json:"cpu_steal"`                          // % of CPU stolen by hypervisor (0 is a real reading)
	CPUIowait     float64    `json:"cpu_iowait"`                         // % of CPU waiting on disk (0 is a real reading)
	MemPressure   *float64   `json:"mem_pressure_some,omitempty"`        // PSI memory stall %10s (nil if no PSI)
	MemPSI300     *float64   `json:"mem_pressure_some_avg300,omitempty"` // PSI memory stall, 5-minute average (sustained signal)
	CtxSwitches   *float64   `json:"context_switches_per_sec,omitempty"` // context switches/sec (needs a prior sample)
	CPUThrottled  *float64   `json:"cpu_throttled_percent,omitempty"`    // % of CFS periods throttled (cgroup; nil if none)
	DiskAwaitMs   *float64   `json:"disk_await_ms,omitempty"`            // avg ms per I/O on the busiest disk (interval delta)
	DiskAwaitOps  *uint64    `json:"disk_await_ops,omitempty"`           // I/Os that disk completed in the interval (sample size behind DiskAwaitMs)
	DiskUtilPct   *float64   `json:"disk_util_percent,omitempty"`        // % of wall time the busiest disk was doing I/O (saturation)
	FDUsedPercent *float64   `json:"fd_used_percent,omitempty"`          // open file descriptors as % of the system max
	ThermThrottle *int       `json:"thermal_throttle_events,omitempty"`  // CPU thermal-throttle events this interval (0 = none)
	ProcsBlocked  *int       `json:"procs_blocked,omitempty"`            // processes in uninterruptible (D-state) sleep now
	PidUsedPct    *float64   `json:"pid_used_percent,omitempty"`         // live tasks as % of kernel pid_max (near 100% = can't fork)
	ZombieProcs   *int       `json:"zombie_procs,omitempty"`             // processes in Z (defunct) state — a broken reaper leaks PIDs
	Disks         []DiskInfo `json:"disks"`
	LoadAvg       [3]float64 `json:"load_avg"`
	TempC         float64    `json:"temp_c,omitempty"`          // hottest sensor; 0 if none (VMs)
	GPUPercent    float64    `json:"gpu_percent,omitempty"`     // NVIDIA util %; 0 if no nvidia-smi
	BatteryPct    float64    `json:"battery_percent,omitempty"` // 0 if no battery (desktops/VMs)
	CollectedAt   time.Time  `json:"collected_at"`
}

// DiskInfo holds per-mount-point disk usage.
type DiskInfo struct {
	MountPoint string  `json:"mount_point"`
	Device     string  `json:"device"`
	FSType     string  `json:"fstype"`
	Total      uint64  `json:"total_bytes"`
	Used       uint64  `json:"used_bytes"`
	Free       uint64  `json:"free_bytes"`
	Percent    float64 `json:"percent"`
}

// SystemCollector collects OS-level system metrics.
type SystemCollector struct{}

func NewSystemCollector() *SystemCollector {
	return &SystemCollector{}
}

func (s *SystemCollector) Name() string { return "system" }

func (s *SystemCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &SystemInfo{
		Arch:        runtime.GOARCH,
		CollectedAt: time.Now().UTC(),
	}

	// Hostname
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("hostname: %w", err)
	}
	info.Hostname = hostname
	info.IPAddress = primaryIP()
	info.PublicIP = CloudPublicIP()
	info.CloudResource = CloudResourceID()

	// Host info (OS, kernel, uptime)
	hostInfo, err := host.InfoWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("host info: %w", err)
	}
	info.OS = hostInfo.OS
	info.Platform = hostInfo.Platform + " " + hostInfo.PlatformVersion
	info.Kernel = hostInfo.KernelVersion
	info.Uptime = hostInfo.Uptime

	// CPU — measured over the whole interval SINCE THE LAST heartbeat, not a short
	// in-line sample. A 200ms sample taken here would land mid-collection, while
	// the agent is busy spawning its other collectors (systemctl/docker/ss/…), and
	// systematically read ~80-99% busy even on an idle box. The /proc/stat delta
	// against the previous reading reflects true steady-state load instead.
	info.CPUCores = runtime.NumCPU()

	// CPU model/clock — identity, not a metric, so read once per process
	// lifetime (/proc/cpuinfo doesn't change) rather than every heartbeat.
	cpuModelOnce.Do(func() {
		if infos, e := cpu.InfoWithContext(ctx); e == nil && len(infos) > 0 {
			cpuModelCached = strings.TrimSpace(infos[0].ModelName)
			cpuMhzCached = infos[0].Mhz
		}
	})
	info.CPUModel = cpuModelCached
	info.CPUMhz = cpuMhzCached

	cur, errC := cpu.TimesWithContext(ctx, false)
	if errC == nil && len(cur) > 0 {
		cpuBaselineMu.Lock()
		prev := cpuBaseline
		c := cur[0]
		cpuBaseline = &c
		cpuBaselineMu.Unlock()
		if prev != nil {
			info.CPUPercent = cpuBusyPercent(*prev, cur[0])
			info.CPUSteal, info.CPUIowait = cpuStealIowait(*prev, cur[0])
		} else if p, e := cpu.PercentWithContext(ctx, 200*time.Millisecond, false); e == nil && len(p) > 0 {
			// First heartbeat of this process — no interval yet; use a short sample
			// so the value isn't blank until the next heartbeat establishes a delta.
			info.CPUPercent = p[0]
		}
	}

	// Memory
	memStats, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("memory: %w", err)
	}
	info.MemTotal = memStats.Total
	info.MemUsed = memStats.Used
	info.MemPercent = memStats.UsedPercent
	info.MemAvailable = memStats.Available

	swapStats, err := mem.SwapMemoryWithContext(ctx)
	if err == nil {
		info.SwapTotal = swapStats.Total
		info.SwapUsed = swapStats.Used
	}

	// Memory pressure (PSI): the fraction of the last 10s in which at least one
	// task stalled on memory. A direct, low-noise stall signal — unlike mem% it
	// distinguishes "using RAM" from "starved for RAM". Linux ≥4.20 only.
	if data, e := os.ReadFile("/proc/pressure/memory"); e == nil {
		if p, ok := parsePSISome(string(data)); ok {
			info.MemPressure = &p
		}
		// The 5-minute average too: avg10 alone trips on a single GC pause or
		// cache drop, so the API judges sustained stall on avg300.
		if p, ok := parsePSISomeAvg(string(data), "avg300"); ok {
			info.MemPSI300 = &p
		}
	}

	// Context switches/sec — the delta of /proc/stat "ctxt" over the interval.
	// Also read procs_blocked (processes stuck in uninterruptible I/O sleep now).
	if data, e := os.ReadFile("/proc/stat"); e == nil {
		if ctxt, ok := parseCtxt(string(data)); ok {
			now := time.Now()
			ctxtMu.Lock()
			prev, prevAt := ctxtPrev, ctxtPrevAt
			ctxtPrev, ctxtPrevAt = ctxt, now
			ctxtMu.Unlock()
			if !prevAt.IsZero() && ctxt >= prev {
				if dt := now.Sub(prevAt).Seconds(); dt > 0 {
					rate := float64(ctxt-prev) / dt
					info.CtxSwitches = &rate
				}
			}
		}
		if b, ok := parseProcsBlocked(string(data)); ok {
			info.ProcsBlocked = &b
		}
	}

	// Thermal throttling — hardware throttle-event counter (Intel/AMD x86 bare
	// metal). A rising count means the CPU is being throttled by heat.
	if cnt, ok := readThermalThrottleCount(); ok {
		thermMu.Lock()
		prev, had := thermPrev, thermHad
		thermPrev, thermHad = cnt, true
		thermMu.Unlock()
		if had && cnt >= prev {
			ev := int(cnt - prev)
			info.ThermThrottle = &ev
		}
	}

	// CPU throttling — fraction of CFS scheduling periods throttled (cgroup CPU
	// quota). Stays 0 on hosts with no CPU limit; meaningful for capped containers.
	if periods, throttled, ok := parseCgroupCPUStat(readCgroupCPUStat()); ok {
		thrMu.Lock()
		pp, pt, had := thrPeriodsPrev, thrThrottledPrev, thrHad
		thrPeriodsPrev, thrThrottledPrev, thrHad = periods, throttled, true
		thrMu.Unlock()
		if had && periods >= pp {
			var pct float64
			if dPer := periods - pp; dPer > 0 {
				pct = float64(throttled-pt) / float64(dPer) * 100
			}
			info.CPUThrottled = &pct
		}
	}

	// File-descriptor pressure: allocated / max from /proc/sys/fs/file-nr. A
	// silent killer — apps stop accepting connections as they near the limit.
	if data, e := os.ReadFile("/proc/sys/fs/file-nr"); e == nil {
		if pct, ok := parseFileNr(string(data)); ok {
			info.FDUsedPercent = &pct
		}
	}

	// Process-table pressure: live tasks vs pid_max (near 100% = fork() fails,
	// no new processes/threads) and a count of zombie (defunct) processes.
	if pct, ok := pidUsedPercent(); ok {
		info.PidUsedPct = &pct
	}
	if z, ok := countZombies(); ok {
		info.ZombieProcs = &z
	}

	// Disk I/O latency: average ms per I/O on the busiest physical disk over the
	// interval (/proc/diskstats delta). The clearest "the disk is slow" signal.
	if data, e := os.ReadFile("/proc/diskstats"); e == nil {
		cur := parseDiskStats(string(data))
		now := time.Now()
		diskStatMu.Lock()
		worst, ops, ok := worstDiskAwaitOps(diskStatPrev, cur)
		util, utilOK := 0.0, false
		if !diskStatPrevAt.IsZero() {
			util, utilOK = worstDiskUtil(diskStatPrev, cur, now.Sub(diskStatPrevAt).Seconds()*1000)
		}
		diskStatPrev = cur
		diskStatPrevAt = now
		diskStatMu.Unlock()
		if ok {
			info.DiskAwaitMs = &worst
			info.DiskAwaitOps = &ops
		}
		if utilOK {
			info.DiskUtilPct = &util
		}
	}

	// Disks (skip pseudo filesystems, container-runtime bind-mounts/overlays —
	// e.g. /run/docker/runtime-runc/moby/<id>/... — which are ephemeral runc
	// artifacts, and read-only-by-design filesystems like squashfs — every
	// installed snap package version is its own 100%-full squashfs loop mount,
	// not storage an operator can act on).
	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err == nil {
		for _, p := range partitions {
			if pseudoFS[p.Fstype] || readOnlyByDesign[p.Fstype] || isContainerRuntimeMount(p.Mountpoint) ||
				strings.HasPrefix(p.Mountpoint, "/snap/") || strings.HasPrefix(p.Mountpoint, "/var/lib/snapd/") ||
				strings.HasPrefix(p.Mountpoint, "/sys") || strings.HasPrefix(p.Mountpoint, "/proc") || strings.HasPrefix(p.Mountpoint, "/dev") {
				continue
			}
			usage, err := disk.UsageWithContext(ctx, p.Mountpoint)
			if err != nil {
				continue
			}
			info.Disks = append(info.Disks, DiskInfo{
				MountPoint: p.Mountpoint,
				Device:     p.Device,
				FSType:     p.Fstype,
				Total:      usage.Total,
				Used:       usage.Used,
				Free:       usage.Free,
				Percent:    usage.UsedPercent,
			})
		}
	}

	// Load average (1, 5, 15 min). Linux-only; absent on some platforms.
	if avg, err := load.AvgWithContext(ctx); err == nil && avg != nil {
		info.LoadAvg = [3]float64{avg.Load1, avg.Load5, avg.Load15}
	}

	// Temperature: hottest hardware sensor. Bare metal exposes coretemp/etc.;
	// most VMs and cloud instances have no sensors, so this stays 0 there.
	if temps, err := host.SensorsTemperaturesWithContext(ctx); err == nil {
		var hottest float64
		for _, t := range temps {
			if t.Temperature > hottest && t.Temperature > 0 && t.Temperature < 150 {
				hottest = t.Temperature
			}
		}
		info.TempC = hottest
	}

	info.GPUPercent = readGPUUtil(ctx)
	info.BatteryPct = readBatteryPercent()

	return info, nil
}

// CPU baseline carried between heartbeats so CPUPercent reflects the true average
// utilization over the whole interval (≈60s), not a short in-line sample.
var (
	cpuBaselineMu sync.Mutex
	cpuBaseline   *cpu.TimesStat

	cpuModelOnce   sync.Once
	cpuModelCached string
	cpuMhzCached   float64
)

func cpuTotal(t cpu.TimesStat) float64 {
	return t.User + t.System + t.Idle + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal + t.Guest + t.GuestNice
}

// cpuBusyPercent returns CPU utilization % between two cumulative samples,
// counting idle + iowait as "not busy" (the standard top/htop definition).
func cpuBusyPercent(b, a cpu.TimesStat) float64 {
	total := cpuTotal(a) - cpuTotal(b)
	if total <= 0 {
		return 0
	}
	idle := (a.Idle + a.Iowait) - (b.Idle + b.Iowait)
	busy := (total - idle) / total * 100
	if busy < 0 {
		return 0
	}
	if busy > 100 {
		return 100
	}
	return busy
}

// Baselines for the rate-based metrics (delta between heartbeats).
var (
	ctxtMu     sync.Mutex
	ctxtPrev   uint64
	ctxtPrevAt time.Time

	thrMu            sync.Mutex
	thrPeriodsPrev   uint64
	thrThrottledPrev uint64
	thrHad           bool

	diskStatMu     sync.Mutex
	diskStatPrev   map[string]diskIO
	diskStatPrevAt time.Time

	thermMu   sync.Mutex
	thermPrev uint64
	thermHad  bool
)

// parseProcsBlocked reads the "procs_blocked N" line from /proc/stat — the count
// of processes in uninterruptible (D-state) sleep, i.e. stuck on I/O. Pure.
func parseProcsBlocked(procStat string) (int, bool) {
	for _, line := range strings.Split(procStat, "\n") {
		if strings.HasPrefix(line, "procs_blocked ") {
			if v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "procs_blocked "))); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// readThermalThrottleCount sums the per-core thermal-throttle event counters from
// sysfs. Present on Intel/AMD x86 bare metal; absent on most VMs/ARM (→ dormant).
func readThermalThrottleCount() (uint64, bool) {
	entries, err := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/thermal_throttle/core_throttle_count")
	if err != nil || len(entries) == 0 {
		return 0, false
	}
	var sum uint64
	found := false
	for _, p := range entries {
		if data, err := os.ReadFile(p); err == nil {
			if v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
				sum += v
				found = true
			}
		}
	}
	return sum, found
}

// diskIO holds the cumulative service-time (ms) and completed-op count for a disk.
type diskIO struct{ ms, ops, ioTicks uint64 }

// Whole physical disks only (skip partitions, loop, ram, dm/zram).
var wholeDiskRe = regexp.MustCompile(`^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme\d+n\d+|mmcblk\d+)$`)

// parseDiskStats reads /proc/diskstats and returns cumulative service-time +
// completed I/Os per whole disk. Columns (0-indexed after split): 2=name,
// 3=reads, 6=ms reading, 7=writes, 10=ms writing. Pure/testable.
func parseDiskStats(content string) map[string]diskIO {
	out := map[string]diskIO{}
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) < 11 || !wholeDiskRe.MatchString(f[2]) {
			continue
		}
		reads, _ := strconv.ParseUint(f[3], 10, 64)
		msRead, _ := strconv.ParseUint(f[6], 10, 64)
		writes, _ := strconv.ParseUint(f[7], 10, 64)
		msWrite, _ := strconv.ParseUint(f[10], 10, 64)
		var ioTicks uint64 // field 12 (ms the device spent doing I/O) → drives %util
		if len(f) >= 13 {
			ioTicks, _ = strconv.ParseUint(f[12], 10, 64)
		}
		out[f[2]] = diskIO{ms: msRead + msWrite, ops: reads + writes, ioTicks: ioTicks}
	}
	return out
}

// worstDiskAwait returns the highest average ms-per-I/O across disks between two
// samples, considering only disks that did ≥10 ops (fewer is statistical noise).
func worstDiskAwait(prev, cur map[string]diskIO) (float64, bool) {
	worst, _, ok := worstDiskAwaitOps(prev, cur)
	return worst, ok
}

// worstDiskAwaitOps is worstDiskAwait plus the number of I/Os the reported
// disk completed in the interval — the sample size behind the average, so the
// API can ignore "slow" readings computed over a handful of operations.
func worstDiskAwaitOps(prev, cur map[string]diskIO) (float64, uint64, bool) {
	if prev == nil {
		return 0, 0, false
	}
	worst, worstOps, found := 0.0, uint64(0), false
	for name, c := range cur {
		p, ok := prev[name]
		if !ok || c.ops < p.ops || c.ms < p.ms {
			continue
		}
		dOps := c.ops - p.ops
		if dOps < 10 {
			continue
		}
		await := float64(c.ms-p.ms) / float64(dOps)
		if !found || await > worst {
			worst, worstOps = await, uint64(dOps)
		}
		found = true
	}
	return worst, worstOps, found
}

// worstDiskUtil returns the highest %util (fraction of wall time the device was
// busy doing I/O) across disks between two samples. io_ticks is in ms; %util =
// Δio_ticks / elapsed_ms × 100, clamped to 100 (multiqueue can overcount).
func worstDiskUtil(prev, cur map[string]diskIO, elapsedMs float64) (float64, bool) {
	if prev == nil || elapsedMs <= 0 {
		return 0, false
	}
	worst, found := 0.0, false
	for name, c := range cur {
		p, ok := prev[name]
		if !ok || c.ioTicks < p.ioTicks {
			continue
		}
		util := float64(c.ioTicks-p.ioTicks) / elapsedMs * 100
		if util > 100 {
			util = 100
		}
		if util > worst {
			worst = util
		}
		found = true
	}
	return worst, found
}

// parseFileNr computes open-fd usage % from /proc/sys/fs/file-nr ("allocated
// free max"). Pure/testable.
func parseFileNr(content string) (float64, bool) {
	f := strings.Fields(content)
	if len(f) < 3 {
		return 0, false
	}
	alloc, e1 := strconv.ParseFloat(f[0], 64)
	max, e2 := strconv.ParseFloat(f[2], 64)
	if e1 != nil || e2 != nil || max <= 0 {
		return 0, false
	}
	return alloc / max * 100, true
}

// parseCtxt extracts the cumulative context-switch count from /proc/stat.
func parseCtxt(procStat string) (uint64, bool) {
	for _, line := range strings.Split(procStat, "\n") {
		if strings.HasPrefix(line, "ctxt ") {
			if v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "ctxt ")), 10, 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// readCgroupCPUStat returns the cgroup cpu.stat contents (v2 path first, then v1).
func readCgroupCPUStat() string {
	for _, p := range []string{"/sys/fs/cgroup/cpu.stat", "/sys/fs/cgroup/cpu/cpu.stat"} {
		if data, err := os.ReadFile(p); err == nil {
			return string(data)
		}
	}
	return ""
}

// parseCgroupCPUStat pulls nr_periods and nr_throttled from cpu.stat. Pure/testable.
func parseCgroupCPUStat(stat string) (periods, throttled uint64, ok bool) {
	var gotP, gotT bool
	for _, line := range strings.Split(stat, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nr_periods":
			if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				periods, gotP = v, true
			}
		case "nr_throttled":
			if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				throttled, gotT = v, true
			}
		}
	}
	return periods, throttled, gotP && gotT
}

// parsePSISome extracts the "some" avg10 value from /proc/pressure/<resource>
// content, i.e. the % of the last 10s in which ≥1 task stalled on the resource.
// Returns (value, true) when the line is present. Pure and testable.
func parsePSISome(data string) (float64, bool) {
	return parsePSISomeAvg(data, "avg10")
}

// parsePSISomeAvg extracts one "some" average (avg10 / avg60 / avg300) from
// /proc/pressure/<resource> content. Pure and testable.
func parsePSISomeAvg(data, key string) (float64, bool) {
	prefix := key + "="
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "some ") {
			for _, f := range strings.Fields(line) {
				if strings.HasPrefix(f, prefix) {
					if v, err := strconv.ParseFloat(strings.TrimPrefix(f, prefix), 64); err == nil {
						return v, true
					}
				}
			}
		}
	}
	return 0, false
}

// cpuStealIowait returns the % of CPU time spent stolen and on iowait between
// two cumulative samples.
func cpuStealIowait(b, a cpu.TimesStat) (steal, iowait float64) {
	total := cpuTotal(a) - cpuTotal(b)
	if total <= 0 {
		return 0, 0
	}
	return (a.Steal - b.Steal) / total * 100, (a.Iowait - b.Iowait) / total * 100
}

// readGPUUtil returns the busiest GPU's utilization % across vendors, or 0 if no
// GPU/driver exposes it. Tries cheap → expensive:
//  1. sysfs gpu_busy_percent — AMD (amdgpu) and newer Intel (xe); no tools, no root.
//  2. nvidia-smi             — NVIDIA discrete GPUs.
//  3. intel_gpu_top          — Intel integrated graphics (i915), which has no
//     sysfs busy %; only used when intel-gpu-tools is installed.
func readGPUUtil(ctx context.Context) float64 {
	var max float64

	// 1. AMD / newer-Intel expose a direct 0-100 busy percentage in sysfs.
	matches, _ := filepath.Glob("/sys/class/drm/card*/device/gpu_busy_percent")
	for _, p := range matches {
		if data, err := os.ReadFile(p); err == nil {
			if v, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil && v > max {
				max = v
			}
		}
	}

	// 2. NVIDIA discrete GPUs.
	if hasBinary("nvidia-smi") {
		if out, err := runCmd(ctx, "nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"); err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if v, err := strconv.ParseFloat(strings.TrimSpace(line), 64); err == nil && v > max {
					max = v
				}
			}
		}
	}

	// 3. Intel integrated graphics (i915) has no sysfs busy %, so fall back to
	//    intel_gpu_top when present (apt install intel-gpu-tools).
	if max == 0 && hasBinary("intel_gpu_top") {
		if v := readIntelGPUTop(ctx); v > max {
			max = v
		}
	}
	return max
}

var gpuBusyRe = regexp.MustCompile(`"busy"\s*:\s*([0-9.]+)`)

// readIntelGPUTop samples intel_gpu_top briefly and returns the busiest engine's
// utilization %. intel_gpu_top streams JSON samples until killed, so we bound it
// with a short timeout and take the highest "busy" value seen across samples.
func readIntelGPUTop(ctx context.Context) float64 {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, _ := runCmd(cctx, "intel_gpu_top", "-J", "-s", "300", "-o", "-")
	var max float64
	for _, m := range gpuBusyRe.FindAllStringSubmatch(string(out), -1) {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil && v > max && v <= 100 {
			max = v
		}
	}
	return max
}

// readBatteryPercent returns the first battery's charge %, or 0 if there is no
// battery (servers, desktops, most VMs).
func readBatteryPercent() float64 {
	const base = "/sys/class/power_supply"
	entries, err := os.ReadDir(base)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !strings.HasPrefix(strings.ToUpper(e.Name()), "BAT") {
			continue
		}
		data, err := os.ReadFile(base + "/" + e.Name() + "/capacity")
		if err != nil {
			continue
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil {
			return v
		}
	}
	return 0
}

// primaryIP returns the host's primary outbound IPv4 (the source IP the kernel
// would use to reach the internet). No packets are sent — the UDP socket just
// resolves the route. Returns "" if it cannot be determined.
func primaryIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// pidUsedPercent returns live tasks as a percentage of the kernel's pid_max.
// The task total is the denominator of /proc/loadavg's "running/total" field;
// pid_max is the ceiling PID allocation wraps at. Near 100% → fork() fails.
func pidUsedPercent() (float64, bool) {
	la, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(la))
	if len(f) < 4 {
		return 0, false
	}
	slash := strings.IndexByte(f[3], '/')
	if slash < 0 {
		return 0, false
	}
	total, err := strconv.ParseFloat(f[3][slash+1:], 64)
	if err != nil {
		return 0, false
	}
	pm, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return 0, false
	}
	max, err := strconv.ParseFloat(strings.TrimSpace(string(pm)), 64)
	if err != nil || max <= 0 {
		return 0, false
	}
	return total / max * 100, true
}

// countZombies counts processes in the Z (defunct) state by scanning
// /proc/<pid>/stat. The state is the first char after the ") " that closes the
// comm field (which itself may contain spaces/parens).
func countZombies() (int, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	z := 0
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue // not a PID dir
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(data)
		i := strings.LastIndexByte(s, ')')
		if i < 0 || i+2 >= len(s) {
			continue
		}
		if s[i+2] == 'Z' {
			z++
		}
	}
	return z, true
}
