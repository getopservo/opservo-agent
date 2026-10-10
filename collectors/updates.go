package collectors

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// UpdatesInfo reports pending OS package updates and whether a reboot is
// required. Best-effort and currently Ubuntu/Debian-focused (update-notifier);
// on systems where it can't tell, Available is false.
type UpdatesInfo struct {
	Available       bool `json:"available"`
	Pending         int  `json:"pending"`
	SecurityPending int  `json:"security_pending"`
	RebootRequired  bool `json:"reboot_required"`
	// Package-hygiene facts for OHS Maintenance rules (Debian/Ubuntu; best-effort).
	BrokenPackages int   `json:"broken_packages"`
	OrphanPackages int   `json:"orphan_packages"`
	LogRotationOK  *bool `json:"log_rotation_ok,omitempty"` // nil if logrotate absent
	// ExtendedSupport: Ubuntu Pro/ESM is attached with ESM security updates
	// enabled, so an otherwise standard-EOL LTS (e.g. 20.04) still gets patches.
	ExtendedSupport bool `json:"extended_support,omitempty"`
	// RebootPendingDays: how long a reboot has been required (age of the flag
	// file). 0 when not pending; lets OHS escalate a long-overdue reboot.
	RebootPendingDays int `json:"reboot_pending_days,omitempty"`
	// MetadataAgeDays: age of the apt package index. A stale index hides new
	// security updates. nil when it can't be determined (non-apt / no data).
	MetadataAgeDays *int `json:"metadata_age_days,omitempty"`
	// BackupStatus: best-effort — "ok" (a backup timer is enabled), "stale" (a
	// backup unit exists but isn't scheduled), or "" (none detected → no claim).
	BackupStatus string `json:"backup_status,omitempty"`
}

type UpdatesCollector struct{}

func NewUpdatesCollector() *UpdatesCollector { return &UpdatesCollector{} }
func (u *UpdatesCollector) Name() string     { return "updates" }

var (
	reUpdates = regexp.MustCompile(`(\d+)\s+update`)
	reNum     = regexp.MustCompile(`(\d+)`)
)

func (u *UpdatesCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &UpdatesInfo{}

	// Reboot required (Ubuntu/Debian leave this flag file after kernel/libc updates).
	for _, p := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
		if fi, err := os.Stat(p); err == nil {
			info.RebootRequired = true
			info.RebootPendingDays = int(time.Since(fi.ModTime()).Hours() / 24)
			break
		}
	}

	// Package hygiene (runs on every path, before the early return below).
	fillPackageHygiene(ctx, info)
	info.ExtendedSupport = detectExtendedSupport()
	info.MetadataAgeDays = aptMetadataAgeDays()
	info.BackupStatus = detectBackupStatus(ctx)

	// Prefer the LIVE apt cache: `apt list --upgradable` reflects an upgrade
	// immediately (a just-upgraded package drops off the list), reads only the
	// local cache (no network), and is accurate. The update-notifier summary
	// below is a cached file that only refreshes on its own timer, so right
	// after `apt-get upgrade` it would still report the old counts — which made
	// a fixed "security updates" recommendation linger until the timer ran.
	if hasBinary("apt") {
		if out, err := sharedAptUpgradable(ctx); err == nil { // shared with packages collector
			info.Available = true
			info.Pending, info.SecurityPending = parseAptUpgradable(string(out))
			return info, nil
		}
	}

	// Fallback (no apt): update-notifier's cached summary.
	// Example: "23 updates can be applied immediately.
	//           5 of these updates are security updates."
	if data, err := os.ReadFile("/var/lib/update-notifier/updates-available"); err == nil {
		text := string(data)
		info.Available = true
		if m := reUpdates.FindStringSubmatch(text); m != nil {
			info.Pending, _ = strconv.Atoi(m[1])
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(strings.ToLower(line), "securit") {
				if m := reNum.FindStringSubmatch(line); m != nil {
					info.SecurityPending, _ = strconv.Atoi(m[1])
					break
				}
			}
		}
	} else if info.RebootRequired {
		// We still know the reboot state even without the updates file.
		info.Available = true
	}

	return info, nil
}

// fillPackageHygiene populates broken/orphan package counts and log-rotation
// health. Debian/Ubuntu-focused; every probe is best-effort.
func fillPackageHygiene(ctx context.Context, info *UpdatesInfo) {
	if hasBinary("dpkg") {
		if out, err := runCmd(ctx, "sh", "-c", "dpkg --audit 2>/dev/null"); err == nil {
			info.BrokenPackages = parseDpkgAudit(string(out))
		}
	}
	if hasBinary("apt-get") {
		if out, err := runCmd(ctx, "sh", "-c", "apt-get -s autoremove 2>/dev/null"); err == nil {
			info.OrphanPackages = parseAutoremoveCount(string(out))
		}
	}
	// Log rotation: only meaningful where logrotate is installed. Healthy = a
	// schedule exists (cron.daily entry or an active systemd timer).
	if hasBinary("logrotate") {
		ok := false
		if _, err := os.Stat("/etc/cron.daily/logrotate"); err == nil {
			ok = true
		} else if out, err := runCmd(ctx, "sh", "-c", "systemctl is-active logrotate.timer 2>/dev/null"); err == nil && strings.TrimSpace(string(out)) == "active" {
			ok = true
		}
		info.LogRotationOK = &ok
	}
}

// parseDpkgAudit counts packages `dpkg --audit` reports as having problems. Its
// output is empty when clean, else a header followed by indented package lines.
func parseDpkgAudit(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		// Package lines are indented; header/blurb lines start at column 0.
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

var reToRemove = regexp.MustCompile(`(\d+)\s+to remove`)

// parseAutoremoveCount extracts the "N to remove" figure from a simulated
// `apt-get -s autoremove` — i.e. how many orphaned packages could be cleaned.
func parseAutoremoveCount(out string) int {
	if m := reToRemove.FindStringSubmatch(out); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// parseAptUpgradable counts upgradable packages and how many come from a security
// suite, from `apt list --upgradable` output. Lines look like:
//
//	pkg/jammy-updates,jammy-security 1.2.3 amd64 [upgradable from: 1.2.0]
func parseAptUpgradable(out string) (pending, security int) {
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		slash := strings.IndexByte(line, '/')
		if slash < 0 {
			continue
		}
		pending++
		// The package's suites sit between the first '/' and the next space.
		suites := line[slash+1:]
		if sp := strings.IndexByte(suites, ' '); sp >= 0 {
			suites = suites[:sp]
		}
		if strings.Contains(strings.ToLower(suites), "security") {
			security++
		}
	}
	return pending, security
}

// detectExtendedSupport reports whether Ubuntu Pro/ESM is attached with an ESM
// security service enabled — meaning an otherwise standard-EOL LTS still
// receives security patches. Best-effort read of the ubuntu-advantage status
// file; false when absent, unattached, or on non-Ubuntu systems.
func detectExtendedSupport() bool {
	data, err := os.ReadFile("/var/lib/ubuntu-advantage/status.json")
	if err != nil {
		return false
	}
	var st struct {
		Attached bool `json:"attached"`
		Services []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"services"`
	}
	if json.Unmarshal(data, &st) != nil || !st.Attached {
		return false
	}
	for _, s := range st.Services {
		if strings.HasPrefix(s.Name, "esm-") && s.Status == "enabled" {
			return true
		}
	}
	return false
}

// aptMetadataAgeDays returns how old the apt package index is, in days. Uses the
// update-success stamp (set on a successful `apt-get update`) when present, else
// the lists dir mtime. nil on non-apt systems or when neither exists.
func aptMetadataAgeDays() *int {
	for _, p := range []string{"/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/lists"} {
		if fi, err := os.Stat(p); err == nil {
			d := int(time.Since(fi.ModTime()).Hours() / 24)
			if d < 0 {
				d = 0
			}
			return &d
		}
	}
	return nil
}

var reBackupUnit = regexp.MustCompile(`(?i)(^|[-_./])(backup|restic|borg(matic)?|duplicity|duplicati|rsnapshot|timeshift|bacula|bareos|rclone)`)

// detectBackupStatus is a best-effort read of whether a backup job is scheduled.
// It never asserts "missing" (too many out-of-band backup methods to be sure);
// it only reports what it can see: "ok" when a backup timer is enabled, "stale"
// when a backup unit exists but isn't scheduled, "" when none is detected.
func detectBackupStatus(ctx context.Context) string {
	if !hasBinary("systemctl") {
		return ""
	}
	out, err := runCmd(ctx, "sh", "-c", "systemctl list-unit-files --type=service,timer --no-legend --no-pager 2>/dev/null")
	if err != nil {
		return ""
	}
	var haveUnit, scheduled bool
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !reBackupUnit.MatchString(f[0]) {
			continue
		}
		haveUnit = true
		if strings.HasSuffix(f[0], ".timer") && (f[1] == "enabled" || f[1] == "static") {
			scheduled = true
		}
	}
	switch {
	case scheduled:
		return "ok"
	case haveUnit:
		return "stale"
	default:
		return ""
	}
}
