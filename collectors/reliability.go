package collectors

import (
	"context"
	"os"
	"regexp"
	"strings"
	"time"
)

// ReliabilityCollector reads kernel/journal signals that the OpsServo Health
// Standard (OHS) reliability & storage rules consume: OOM kills, kernel panics,
// segfaults, filesystem errors, and read-only remounts. It reads the current
// boot's kernel log via journalctl (fallback: dmesg), so it needs no state.
//
// JSON key: "reliability" → snapshot.reliability (read by the Opservo API).
type ReliabilityCollector struct{}

func NewReliabilityCollector() *ReliabilityCollector { return &ReliabilityCollector{} }
func (c *ReliabilityCollector) Name() string         { return "reliability" }

type ReliabilityReport struct {
	OOMKills         int  `json:"oom_kills"`
	KernelPanic      bool `json:"kernel_panic"`
	Segfaults        int  `json:"segfaults"`
	FilesystemErrors bool `json:"filesystem_errors"`
	RemountRO        bool `json:"remount_ro"`
	// Critical-priority (≤2) journal entries in the last 15 minutes — a rolling
	// window, not a since-boot cumulative count, so it clears on its own once a
	// burst stops recurring instead of staying permanently tripped until reboot.
	JournalCritical int `json:"journal_critical"`
	// From the kernel log (this boot): hardware machine-check errors and hung-task
	// (task blocked >120s) events.
	MCEErrors int `json:"mce_errors"`
	HungTasks int `json:"hung_tasks"`
	// Reboots in the last 24h (from journalctl --list-boots); repeated reboots
	// signal crashes/flapping. Core dumps left by crashed processes (coredumpctl).
	RebootsLast24h int `json:"reboots_last_24h"`
	CoreDumps      int `json:"core_dumps"`
	// Per-device hardware I/O failures from the kernel log (this boot) —
	// block-layer I/O errors, SCSI/ATA command failures, EXT4/XFS complaints
	// attributed to a device. One entry per physical disk; the OHS
	// STORAGE_DISKFAIL_001 rule turns this into a single "disk X is failing"
	// alert instead of one alert per recurring log pattern.
	DiskErrors  []DiskError `json:"disk_errors,omitempty"`
	CollectedAt time.Time   `json:"collected_at"`
}

// DiskError aggregates kernel-log evidence that one disk is failing.
type DiskError struct {
	Device    string `json:"device"`     // "sda", "nvme0n1", or "ata1" when the link could not be tied to a block device
	IOErrors  int    `json:"io_errors"`  // block/SCSI/filesystem-level I/O errors
	ATAErrors int    `json:"ata_errors"` // SATA link exceptions / failed commands
	Sample    string `json:"sample"`     // first matching kernel line (≤160 chars)
}

const reliabilityCmdTimeout = 5 * time.Second

func (c *ReliabilityCollector) Collect(ctx context.Context) (interface{}, error) {
	// Kernel ring buffer for THIS boot. journalctl -k is unprivileged-friendly on
	// most distros; dmesg is the fallback where journald isn't present.
	var klog string
	if hasBinary("journalctl") {
		if out, err := runCmdTimeout(ctx, reliabilityCmdTimeout, "journalctl", "-k", "-b", "--no-pager", "-o", "cat"); err == nil {
			klog = string(out)
		}
	}
	if klog == "" && hasBinary("dmesg") {
		if out, err := runCmdTimeout(ctx, reliabilityCmdTimeout, "dmesg", "--ctime"); err == nil {
			klog = string(out)
		}
	}
	if klog == "" {
		// No readable kernel log — return an empty (but valid) report; the OHS
		// rules stay neutral rather than dormant, which is correct: no evidence
		// of a fault this boot.
		return &ReliabilityReport{CollectedAt: time.Now().UTC()}, nil
	}

	r := parseKernelSignals(klog)

	// journalctl priority ≤ 2 (crit/alert/emerg) count in the last 15 minutes,
	// best-effort. A rolling window (not "-b" alone, which is cumulative since
	// boot and — once tripped — can never legitimately drop below threshold
	// again until a reboot, making the finding permanently unresolvable even
	// after the root cause is fixed).
	if hasBinary("journalctl") {
		if out, err := runCmdTimeout(ctx, reliabilityCmdTimeout, "journalctl", "-b", "-p", "2", "--since", "-15min", "--no-pager", "-o", "cat"); err == nil {
			r.JournalCritical = countNonEmptyLines(string(out))
		}
		// Reboots in the last 24h — repeated reboots signal crashes/flapping.
		if out, err := runCmdTimeout(ctx, reliabilityCmdTimeout, "journalctl", "--list-boots", "--no-pager", "--utc"); err == nil {
			r.RebootsLast24h = rebootsWithin(string(out), time.Now().UTC(), 24*time.Hour)
		}
	}

	// Core dumps left by crashed processes (systemd-coredump).
	r.CoreDumps = countCoreDumps(ctx)

	r.CollectedAt = time.Now().UTC()
	return r, nil
}

// rebootsWithin counts boots that STARTED within `window` of `now` from the
// output of `journalctl --list-boots` (one boot per line; the last column is the
// boot's start time). A count of N boots means N-1 reboots in the window.
// Pure/testable — the timestamps are parsed from the text.
func rebootsWithin(listBoots string, now time.Time, window time.Duration) int {
	// A line looks like: " 0 <id> Mon 2026-07-07 09:15:03 UTC—Mon ...". We pull the
	// first "YYYY-MM-DD HH:MM:SS" on the line as the boot start.
	reWhen := regexp.MustCompile(`(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`)
	started := 0
	cutoff := now.Add(-window)
	for _, line := range strings.Split(listBoots, "\n") {
		m := reWhen.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// We pass --utc to journalctl (see the caller), so timestamps are UTC and
		// parse-as-UTC matches the UTC `now`/`cutoff` — correct on non-UTC hosts too
		// (without --utc, local times were mis-read as UTC and the 24h
		// window was skewed by the timezone offset on e.g. IST servers).
		t, err := time.Parse("2006-01-02 15:04:05", m[1])
		if err != nil {
			continue
		}
		if t.After(cutoff) {
			started++
		}
	}
	if started <= 1 {
		return 0 // 0 or 1 boot in the window = no reboot within it
	}
	return started - 1
}

// countCoreDumps returns how many core dumps systemd currently retains. Best-
// effort: uses coredumpctl when present, else counts files in the spool dir.
func countCoreDumps(ctx context.Context) int {
	if hasBinary("coredumpctl") {
		if out, err := runCmdTimeout(ctx, reliabilityCmdTimeout, "coredumpctl", "list", "--no-legend", "--no-pager"); err == nil {
			return countNonEmptyLines(string(out))
		}
	}
	if entries, err := os.ReadDir("/var/lib/systemd/coredump"); err == nil {
		return len(entries)
	}
	return 0
}

var (
	reOOM      = regexp.MustCompile(`(?i)out of memory: killed process|invoked oom-killer|oom-kill:`)
	rePanic    = regexp.MustCompile(`(?i)kernel panic`)
	reSegfault = regexp.MustCompile(`(?i)segfault at |general protection fault|traps:.*trap`)
	reFSErr    = regexp.MustCompile(`(?i)ext4-fs error|xfs.*corrupt|btrfs.*error|i/o error.*dev|filesystem.*error`)
	reRemount  = regexp.MustCompile(`(?i)remount(ing|ed) (filesystem )?read-only|mounting.*read-only`)
	reMCE      = regexp.MustCompile(`(?i)\bhardware error\b|machine check|\bmce:|mce hardware`)
	reHung     = regexp.MustCompile(`(?i)blocked for more than \d+ seconds|hung_task|task .* blocked for`)

	// Disk-failure attribution. Each yields the device name in group 1.
	reDiskIO = []*regexp.Regexp{
		regexp.MustCompile(`(?i)i/o error, dev ([a-z]+[a-z0-9]*), sector`),          // blk_update_request / print_req_error
		regexp.MustCompile(`(?i)buffer i/o error on dev(?:ice)? ([a-z]+[a-z0-9]*)`), // buffer_io_error
		regexp.MustCompile(`(?i)\[(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+)\][^\n]*(?:access beyond end of device|medium error|unhandled sense|failed command|i/o error|unrecovered read error|add\. sense)`),
		regexp.MustCompile(`(?i)(?:ext4-fs|xfs|btrfs)[^\n]*?\(?(?:device |dev )?(sd[a-z]+\d*|vd[a-z]+\d*|xvd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?)\)?[^\n]*(?:error|corrupt|data loss|failed to|i/o error)`),
		regexp.MustCompile(`(?i)(nvme\d+)(?:n\d+)?: (?:i/o cmd|controller is down|device not ready|resetting controller|timeout)`),
	}
	reDiskATA = regexp.MustCompile(`(?i)\b(ata\d+)(?:\.\d+)?: (?:exception emask|failed command|error: \{|status: \{ drdy (?:df )?err|hard resetting link|link is slow to respond)`)
	// Partition suffix → whole disk ("sda1" → "sda", "nvme0n1p2" → "nvme0n1").
	rePartSuffix = regexp.MustCompile(`^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+)\d+$|^(nvme\d+n\d+|mmcblk\d+)p\d+$`)
)

const maxDiskErrorDevices = 8

// wholeDisk strips a partition suffix so per-partition kernel lines aggregate
// onto the physical device.
func wholeDisk(dev string) string {
	if m := rePartSuffix.FindStringSubmatch(dev); m != nil {
		if m[1] != "" {
			return m[1]
		}
		return m[2]
	}
	return dev
}

// diskErrorsFrom attributes I/O and ATA failures in a kernel log to devices.
// ATA link errors name a port ("ata1"), not a block device; when exactly one
// block device has I/O errors they are folded into it (the common single-disk
// case — a real failing drive produced hundreds of ata1 exceptions alongside
// sda I/O errors). Otherwise the port is reported as its own entry.
func diskErrorsFrom(lines []string) []DiskError {
	type acc struct {
		io, ata int
		sample  string
	}
	block := map[string]*acc{}
	ata := map[string]*acc{}
	var blockOrder, ataOrder []string
	get := func(m map[string]*acc, order *[]string, k, line string) *acc {
		a := m[k]
		if a == nil {
			a = &acc{sample: truncateLine(line, 160)}
			m[k] = a
			*order = append(*order, k)
		}
		return a
	}
	for _, line := range lines {
		matched := false
		for _, re := range reDiskIO {
			if m := re.FindStringSubmatch(line); m != nil {
				get(block, &blockOrder, wholeDisk(strings.ToLower(m[1])), line).io++
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if m := reDiskATA.FindStringSubmatch(line); m != nil {
			get(ata, &ataOrder, strings.ToLower(m[1]), line).ata++
		}
	}
	if len(block) == 0 && len(ata) == 0 {
		return nil
	}
	var out []DiskError
	for _, k := range blockOrder {
		a := block[k]
		out = append(out, DiskError{Device: k, IOErrors: a.io, Sample: a.sample})
	}
	if len(out) == 1 {
		for _, k := range ataOrder {
			out[0].ATAErrors += ata[k].ata
		}
	} else {
		for _, k := range ataOrder {
			out = append(out, DiskError{Device: k, ATAErrors: ata[k].ata, Sample: ata[k].sample})
		}
	}
	if len(out) > maxDiskErrorDevices {
		out = out[:maxDiskErrorDevices]
	}
	return out
}

func truncateLine(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// parseKernelSignals counts the reliability-relevant events in a kernel log.
// Pure and testable — no I/O.
func parseKernelSignals(klog string) *ReliabilityReport {
	r := &ReliabilityReport{}
	lines := strings.Split(klog, "\n")
	r.DiskErrors = diskErrorsFrom(lines)
	for _, line := range lines {
		if line == "" {
			continue
		}
		if reOOM.MatchString(line) {
			// Count only the actual kill lines, not the "invoked oom-killer" preamble.
			if strings.Contains(strings.ToLower(line), "killed process") {
				r.OOMKills++
			}
		}
		if rePanic.MatchString(line) {
			r.KernelPanic = true
		}
		if reSegfault.MatchString(line) {
			r.Segfaults++
		}
		if reFSErr.MatchString(line) {
			r.FilesystemErrors = true
		}
		if reRemount.MatchString(line) {
			r.RemountRO = true
		}
		if reMCE.MatchString(line) {
			r.MCEErrors++
		}
		if reHung.MatchString(line) {
			r.HungTasks++
		}
	}
	return r
}

func countNonEmptyLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
