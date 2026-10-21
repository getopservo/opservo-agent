package collectors

import (
	"bufio"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/getopservo/opservo-agent/buffer"
)

// ChangesCollector reports WHAT CHANGED on the box, with timestamps, so the
// API can put "nginx.conf edited 14:02" next to "nginx failed 14:03". Two
// sources the agent can read without any configuration:
//
//   - package manager history: /var/log/dpkg.log (Debian/Ubuntu) and
//     /var/log/dnf.rpm.log (RHEL/Fedora), tailed with a buffer cursor like a
//     log file, so each install / upgrade / remove ships once;
//   - recently modified configuration files under a fixed set of directories
//     (web server, SSH, systemd units, cron, PHP, databases, sudoers, firewall,
//     authorized_keys). Only the PATH, mtime and size are reported — never the
//     contents — and the API de-duplicates on (path, mtime), so re-reporting a
//     file for 48 h costs nothing and survives an agent restart.
//
// Inventory-level changes (a service appearing, a port opening, a container
// image changing, a deploy) are derived server-side from consecutive
// snapshots; nothing here duplicates them.
//
// JSON key: "changes" → snapshot.changes.
type ChangesCollector struct {
	buf *buffer.Buffer
	// now is injectable for tests.
	now func() time.Time
}

func NewChangesCollector(buf *buffer.Buffer) *ChangesCollector {
	return &ChangesCollector{buf: buf, now: time.Now}
}
func (c *ChangesCollector) Name() string { return "changes" }

// PackageEvent is one package-manager action with its timestamp.
type PackageEvent struct {
	Action  string `json:"action"` // install | upgrade | remove
	Package string `json:"package"`
	From    string `json:"from,omitempty"` // previous version (upgrade / remove)
	To      string `json:"to,omitempty"`   // new version (install / upgrade)
	At      string `json:"at"`             // RFC 3339, UTC
}

// FileChange is a configuration file whose mtime is recent. No contents.
type FileChange struct {
	Path       string `json:"path"`
	Area       string `json:"area"` // nginx | apache | ssh | systemd | cron | php | mysql | postgres | redis | sudo | firewall | access | system | …
	ModifiedAt string `json:"modified_at"`
	SizeBytes  int64  `json:"size_bytes"`
	Symlink    bool   `json:"symlink,omitempty"` // e.g. a site enabled in sites-enabled
}

type ChangesInfo struct {
	Available   bool           `json:"available"`
	Packages    []PackageEvent `json:"packages"`
	ConfigFiles []FileChange   `json:"config_files"`
}

const (
	// A config file counts as "recently modified" for this long; the API keeps
	// the first sighting, so the window only has to cover a missed heartbeat
	// or two plus an agent restart.
	configRecentWindow = 48 * time.Hour
	maxConfigFiles     = 100
	maxPackageEvents   = 200
	// With no cursor yet (first heartbeat after install) only the tail of the
	// package log is read, and only events this recent are shipped, so a
	// two-year-old dpkg.log doesn't arrive as 20,000 "changes" at once.
	firstTailBytes  = 256 * 1024
	firstTailWindow = 7 * 24 * time.Hour
)

// Watched configuration roots → area label. Directories are walked three
// levels deep; single files are stat'ed.
var configRoots = []struct{ path, area string }{
	{"/etc/nginx", "nginx"},
	{"/etc/apache2", "apache"},
	{"/etc/httpd", "apache"},
	{"/etc/caddy", "caddy"},
	{"/etc/ssh", "ssh"},
	{"/etc/systemd/system", "systemd"},
	{"/etc/crontab", "cron"},
	{"/etc/cron.d", "cron"},
	{"/etc/cron.daily", "cron"},
	{"/etc/cron.hourly", "cron"},
	{"/var/spool/cron", "cron"},
	{"/etc/php", "php"},
	{"/etc/mysql", "mysql"},
	{"/etc/my.cnf", "mysql"},
	{"/etc/my.cnf.d", "mysql"},
	{"/etc/postgresql", "postgres"},
	{"/etc/redis", "redis"},
	{"/etc/supervisor", "supervisor"},
	{"/etc/docker/daemon.json", "docker"},
	{"/etc/letsencrypt/renewal", "tls"},
	{"/etc/sudoers", "sudo"},
	{"/etc/sudoers.d", "sudo"},
	{"/etc/ufw", "firewall"},
	{"/etc/fail2ban", "firewall"},
	{"/etc/hosts", "system"},
	{"/etc/fstab", "system"},
	{"/etc/resolv.conf", "system"},
	{"/etc/sysctl.conf", "system"},
	{"/etc/sysctl.d", "system"},
	{"/etc/environment", "system"},
	{"/etc/passwd", "access"},
	{"/etc/group", "access"},
}

func (c *ChangesCollector) Collect(ctx context.Context) (interface{}, error) {
	now := c.now()
	info := &ChangesInfo{Packages: []PackageEvent{}, ConfigFiles: []FileChange{}}

	if _, err := os.Stat("/var/log/dpkg.log"); err == nil {
		info.Available = true
		lines, first := c.newLines("/var/log/dpkg.log")
		info.Packages = append(info.Packages, filterRecent(parseDpkgLog(lines, time.Local), now, first)...)
	}
	if _, err := os.Stat("/var/log/dnf.rpm.log"); err == nil {
		info.Available = true
		lines, first := c.newLines("/var/log/dnf.rpm.log")
		info.Packages = append(info.Packages, filterRecent(parseDnfRpmLog(lines), now, first)...)
	}
	if len(info.Packages) > maxPackageEvents {
		info.Packages = info.Packages[len(info.Packages)-maxPackageEvents:]
	}

	roots := make([]struct{ path, area string }, 0, len(configRoots)+8)
	roots = append(roots, configRoots...)
	for _, p := range authorizedKeyFiles() {
		roots = append(roots, struct{ path, area string }{p, "access"})
	}
	info.ConfigFiles = recentConfigFiles(ctx, roots, now, configRecentWindow, maxConfigFiles)
	if len(info.ConfigFiles) > 0 {
		info.Available = true
	}
	return info, nil
}

// authorizedKeyFiles lists the authorized_keys files of root and every home
// directory (paths only; contents are the users collector's business and are
// never shipped from here either).
func authorizedKeyFiles() []string {
	out := []string{"/root/.ssh/authorized_keys"}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, filepath.Join("/home", e.Name(), ".ssh", "authorized_keys"))
			}
		}
	}
	return out
}

// newLines returns the lines appended to path since the last heartbeat (buffer
// cursor; rotation restarts from 0). `first` is true when there was no cursor
// yet, so the caller should keep only recent events.
func (c *ChangesCollector) newLines(path string) (lines []string, first bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	size := fi.Size()
	var offset, prevSize int64
	if c.buf != nil {
		offset, prevSize, _ = c.buf.Cursor(path)
	}
	first = prevSize == 0 && offset == 0
	if size < prevSize || offset > size {
		offset, first = 0, true // rotated or truncated
	}
	skipPartial := false
	if first && size-offset > firstTailBytes {
		offset = size - firstTailBytes
		skipPartial = true
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, first
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, first
		}
	}
	rd := bufio.NewReaderSize(f, 64*1024)
	if skipPartial {
		if _, err := rd.ReadString('\n'); err != nil {
			return nil, first
		}
	}
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	if c.buf != nil {
		_ = c.buf.SetCursor(path, size, size)
	}
	return lines, first
}

// filterRecent drops events older than firstTailWindow on a first read (no
// cursor); with a cursor every new line is a genuine new event.
func filterRecent(events []PackageEvent, now time.Time, first bool) []PackageEvent {
	if !first {
		return events
	}
	cutoff := now.Add(-firstTailWindow)
	out := events[:0]
	for _, e := range events {
		if t, err := time.Parse(time.RFC3339, e.At); err == nil && !t.Before(cutoff) {
			out = append(out, e)
		}
	}
	return out
}

// parseDpkgLog reads dpkg.log action lines:
//
//	2026-10-18 10:00:01 upgrade nginx:amd64 1.18.0-6ubuntu14.4 1.18.0-6ubuntu14.5
//	2026-10-18 10:00:05 install htop:amd64 <none> 3.0.5-7build2
//	2026-10-18 10:00:09 remove telnet:amd64 0.17-44build1 <none>
//
// Timestamps are local time with no zone, hence loc. Status/trigger/startup
// lines are ignored.
func parseDpkgLog(lines []string, loc *time.Location) []PackageEvent {
	var out []PackageEvent
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		action := f[2]
		switch action {
		case "install", "upgrade", "remove", "purge":
		default:
			continue
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", f[0]+" "+f[1], loc)
		if err != nil {
			continue
		}
		name := f[3]
		if i := strings.IndexByte(name, ':'); i > 0 {
			name = name[:i] // strip :amd64
		}
		ev := PackageEvent{Action: action, Package: name, At: t.UTC().Format(time.RFC3339)}
		if action == "purge" {
			ev.Action = "remove"
		}
		if f[4] != "<none>" {
			ev.From = f[4]
		}
		if f[5] != "<none>" {
			ev.To = f[5]
		}
		if ev.Action == "remove" && ev.From == "" && ev.To != "" {
			ev.From, ev.To = ev.To, "" // purge after remove logs the version in the "new" slot
		}
		out = append(out, ev)
	}
	return out
}

// parseDnfRpmLog reads dnf.rpm.log:
//
//	2026-10-18T10:00:00+0000 SUBDEBUG Upgraded: nginx-1:1.20.1-14.el9.x86_64
//	2026-10-18T10:00:00+0000 SUBDEBUG Installed: htop-3.2.2-1.el9.x86_64
//	2026-10-18T10:00:00+0000 SUBDEBUG Erase: telnet-0.17-85.el9.x86_64
//
// "Upgrade:" (old version) and "Obsoleted:" lines are skipped; "Upgraded:"
// carries the new version. Old and new are logged on separate lines, so an
// upgrade event here has To only.
func parseDnfRpmLog(lines []string) []PackageEvent {
	var out []PackageEvent
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		var action string
		switch f[2] {
		case "Installed:", "Reinstalled:":
			action = "install"
		case "Upgraded:", "Downgraded:":
			action = "upgrade"
		case "Erase:", "Erased:", "Removed:":
			action = "remove"
		default:
			continue
		}
		ts := f[0]
		// dnf writes +0000 without a colon; RFC 3339 needs one.
		if n := len(ts); n > 5 && (ts[n-5] == '+' || ts[n-5] == '-') {
			ts = ts[:n-2] + ":" + ts[n-2:]
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		name, ver := splitNEVRA(f[3])
		ev := PackageEvent{Action: action, Package: name, At: t.UTC().Format(time.RFC3339)}
		if action == "remove" {
			ev.From = ver
		} else {
			ev.To = ver
		}
		out = append(out, ev)
	}
	return out
}

// splitNEVRA splits "name-[epoch:]version-release.arch" into name and
// "version-release" (epoch kept, arch dropped).
func splitNEVRA(s string) (name, version string) {
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		s = s[:i] // drop .arch
	}
	rel := strings.LastIndexByte(s, '-')
	if rel <= 0 {
		return s, ""
	}
	ver := strings.LastIndexByte(s[:rel], '-')
	if ver <= 0 {
		return s[:rel], s[rel+1:]
	}
	return s[:ver], s[ver+1:]
}

// recentConfigFiles walks the roots (≤ 3 levels, bounded) and returns the
// files and symlinks modified within `within` of now, newest first, capped.
func recentConfigFiles(ctx context.Context, roots []struct{ path, area string }, now time.Time, within time.Duration, limit int) []FileChange {
	cutoff := now.Add(-within)
	var out []FileChange
	visited := 0
	for _, r := range roots {
		if ctx.Err() != nil {
			break
		}
		base, err := os.Lstat(r.path)
		if err != nil {
			continue
		}
		if !base.IsDir() {
			if fc, ok := fileChange(r.path, r.area, base, cutoff); ok {
				out = append(out, fc)
			}
			continue
		}
		depth := strings.Count(filepath.Clean(r.path), string(os.PathSeparator))
		_ = filepath.WalkDir(r.path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			visited++
			if visited > 5000 || ctx.Err() != nil {
				return filepath.SkipAll
			}
			if d.IsDir() {
				if strings.Count(p, string(os.PathSeparator))-depth >= 3 {
					return filepath.SkipDir
				}
				return nil
			}
			fi, err := os.Lstat(p)
			if err != nil {
				return nil
			}
			if fc, ok := fileChange(p, r.area, fi, cutoff); ok {
				out = append(out, fc)
			}
			return nil
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModifiedAt > out[j].ModifiedAt })
	if len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []FileChange{}
	}
	return out
}

func fileChange(p, area string, fi fs.FileInfo, cutoff time.Time) (FileChange, bool) {
	mode := fi.Mode()
	isLink := mode&os.ModeSymlink != 0
	if !mode.IsRegular() && !isLink {
		return FileChange{}, false
	}
	if fi.ModTime().Before(cutoff) {
		return FileChange{}, false
	}
	// Editor leftovers and package-manager backups are churn, not changes.
	name := filepath.Base(p)
	if strings.HasSuffix(name, "~") || strings.HasSuffix(name, ".swp") || strings.HasSuffix(name, ".dpkg-old") || strings.HasSuffix(name, ".dpkg-dist") || strings.HasSuffix(name, ".rpmnew") || strings.HasSuffix(name, ".rpmsave") || strings.HasPrefix(name, ".") && !strings.HasSuffix(p, "authorized_keys") {
		return FileChange{}, false
	}
	return FileChange{
		Path:       p,
		Area:       area,
		ModifiedAt: fi.ModTime().UTC().Format(time.RFC3339),
		SizeBytes:  fi.Size(),
		Symlink:    isLink,
	}, true
}
