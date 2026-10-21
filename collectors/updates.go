package collectors

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"sort"
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

	// Patch status detail (18 Oct 2026). Which security updates are pending,
	// not just how many: the kernel and the packages attackers reach first
	// (OpenSSL, OpenSSH, glibc, sudo, the web server, PHP, the databases) are
	// tagged so the dashboard can offer "install these first" as one command.
	// apt: parsed from `apt list --upgradable`; dnf/yum: `dnf updateinfo list
	// --security`. Capped at maxSecurityPackages, kernel + high-exposure first.
	SecurityPackages    []PendingUpdate `json:"security_packages,omitempty"`
	KernelUpdatePending bool            `json:"kernel_update_pending,omitempty"`
	HighExposurePending []string        `json:"high_exposure_pending,omitempty"`
}

// PendingUpdate is one package with a newer security version available.
type PendingUpdate struct {
	Name         string `json:"name"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	Kernel       bool   `json:"kernel,omitempty"`
	HighExposure bool   `json:"high_exposure,omitempty"`
}

const maxSecurityPackages = 60

// reKernelPkg: the running-kernel packages on Debian/Ubuntu and RHEL-likes.
var reKernelPkg = regexp.MustCompile(`^(linux-image|linux-generic|linux-virtual|linux-aws|linux-gcp|linux-azure|linux-oracle|linux-kvm|linux-modules|linux-headers|kernel|kernel-core|kernel-modules)(-|$)`)

// reHighExposure: packages whose vulnerabilities are reachable from the network
// or give root at once — what an attacker scans for, and what to patch first.
var reHighExposure = regexp.MustCompile(`^(openssl|libssl[0-9.]*|openssh-server|openssh|libc6|libc-bin|glibc|sudo|polkit|policykit-1|systemd|dbus|bash|nginx|nginx-[a-z]+|apache2|httpd|caddy|haproxy|php[0-9.]*(-fpm|-cli|-common|-mysql)?|libphp[0-9.]*|mysql-server[0-9.-]*|mariadb-server[0-9.-]*|percona-server-server.*|postgresql(-[0-9.]+)?(-server)?|redis-server|redis|mongodb-org-server|memcached|docker-ce|docker\.io|containerd(\.io)?|runc|nodejs|node|curl|libcurl[0-9a-z]*|wget|git|libxml2|zlib1g|libexpat1|expat|bind9|named|postfix|exim4|dovecot-core|vsftpd|samba|smbd|kubelet|libgnutls[0-9]*|gnutls|libnss3|nss|libkrb5-[0-9]|krb5-libs|xz-utils|liblzma[0-9]*|tar|unzip|libtiff[0-9]*|imagemagick|ghostscript|libwebp[0-9]*|libpng[0-9-]*|ca-certificates)$`)

func isKernelPackage(name string) bool { return reKernelPkg.MatchString(name) }
func isHighExposure(name string) bool  { return reHighExposure.MatchString(name) }

// fillPatchDetail sets the detail fields from a list of pending security
// updates: kernel/high-exposure first, capped, plus the two summary fields.
func fillPatchDetail(info *UpdatesInfo, sec []PendingUpdate) {
	seen := map[string]bool{}
	for i := range sec {
		sec[i].Kernel = isKernelPackage(sec[i].Name)
		sec[i].HighExposure = isHighExposure(sec[i].Name)
		if sec[i].Kernel {
			info.KernelUpdatePending = true
		}
		if sec[i].HighExposure && !seen[sec[i].Name] {
			seen[sec[i].Name] = true
			info.HighExposurePending = append(info.HighExposurePending, sec[i].Name)
		}
	}
	sort.SliceStable(sec, func(i, j int) bool {
		ri, rj := patchRank(sec[i]), patchRank(sec[j])
		if ri != rj {
			return ri < rj
		}
		return sec[i].Name < sec[j].Name
	})
	if len(sec) > maxSecurityPackages {
		sec = sec[:maxSecurityPackages]
	}
	info.SecurityPackages = sec
}

func patchRank(p PendingUpdate) int {
	switch {
	case p.Kernel:
		return 0
	case p.HighExposure:
		return 1
	}
	return 2
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
			var sec []PendingUpdate
			info.Pending, info.SecurityPending, sec = parseAptUpgradableDetail(string(out))
			fillPatchDetail(info, sec)
			return info, nil
		}
	}

	// RHEL / Fedora / Amazon Linux: dnf (or yum). `check-update` exits 100 when
	// updates exist, so its error is expected; `updateinfo list --security`
	// names the security ones; `needs-restarting -r` exits 1 when a reboot is
	// due (no flag file on these systems).
	if dnf := firstBinary("dnf", "yum"); dnf != "" {
		info.Available = true
		if out, _ := runCmdTimeout(ctx, 10*time.Second, dnf, "-q", "check-update"); len(out) > 0 {
			info.Pending = parseDnfCheckUpdate(string(out))
		}
		if out, err := runCmdTimeout(ctx, 10*time.Second, dnf, "-q", "updateinfo", "list", "--security"); err == nil || len(out) > 0 {
			sec := parseDnfUpdateinfo(string(out))
			info.SecurityPending = len(sec)
			fillPatchDetail(info, sec)
		}
		if !info.RebootRequired && hasBinary("needs-restarting") {
			if _, err := runCmdTimeout(ctx, 10*time.Second, "needs-restarting", "-r"); err != nil {
				info.RebootRequired = true
			}
		}
		return info, nil
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
	pending, security, _ = parseAptUpgradableDetail(out)
	return pending, security
}

var reUpgradableFrom = regexp.MustCompile(`\[upgradable from: ([^\]]+)\]`)

// parseAptUpgradableDetail is parseAptUpgradable plus the security packages
// themselves (name, current → new version). Kernel / high-exposure tags are
// filled by fillPatchDetail.
func parseAptUpgradableDetail(out string) (pending, security int, sec []PendingUpdate) {
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
		rest := line[slash+1:]
		suites := rest
		if sp := strings.IndexByte(rest, ' '); sp >= 0 {
			suites = rest[:sp]
			rest = strings.TrimSpace(rest[sp+1:])
		} else {
			rest = ""
		}
		if !strings.Contains(strings.ToLower(suites), "security") {
			continue
		}
		security++
		p := PendingUpdate{Name: line[:slash]}
		if f := strings.Fields(rest); len(f) > 0 {
			p.To = f[0]
		}
		if m := reUpgradableFrom.FindStringSubmatch(rest); m != nil {
			p.From = m[1]
		}
		sec = append(sec, p)
	}
	return pending, security, sec
}

// firstBinary returns the first name on PATH, or "".
func firstBinary(names ...string) string {
	for _, n := range names {
		if hasBinary(n) {
			return n
		}
	}
	return ""
}

// parseDnfCheckUpdate counts the package lines of `dnf -q check-update`:
//
//	nginx.x86_64        1:1.20.1-14.el9        appstream
//	Obsoleting Packages
//	…
//
// Lines after "Obsoleting Packages" are skipped (they repeat packages).
func parseDnfCheckUpdate(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
		if f := strings.Fields(line); len(f) == 3 && strings.Contains(f[0], ".") {
			n++
		}
	}
	return n
}

// parseDnfUpdateinfo reads `dnf -q updateinfo list --security`:
//
//	RHSA-2026:1234 Important/Sec. openssl-1:3.0.7-28.el9.x86_64
//	FEDORA-2026-abcd Moderate/Sec.  curl-8.6.0-5.fc40.x86_64
//
// One advisory per line; the same package can appear under several
// advisories, so names are de-duplicated (highest line wins, versions equal).
func parseDnfUpdateinfo(out string) []PendingUpdate {
	seen := map[string]bool{}
	var sec []PendingUpdate
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.Contains(f[1], "Sec") {
			continue
		}
		name, ver := splitNEVRA(f[len(f)-1])
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		sec = append(sec, PendingUpdate{Name: name, To: ver})
	}
	return sec
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
