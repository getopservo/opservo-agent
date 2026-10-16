package collectors

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// PM2 is usually installed per user (nvm, ~/.npm-global) and each user runs
// their own daemon with its own PM2_HOME, so `pm2 jlist` as root sees nothing
// on most servers. Instead we find every running PM2 daemon ("PM2 vX: God
// Daemon (<PM2_HOME>)") in /proc and ask THAT daemon, through its own pm2
// CLI, as the user who owns it. Read-only: `jlist` only lists processes. We
// only ever call it while the daemon's rpc.sock exists, because a pm2 CLI
// that finds no daemon starts one.

// pm2Daemon is one running PM2 God Daemon.
type pm2Daemon struct {
	PID  int
	Home string // PM2_HOME, e.g. /home/ubuntu/.pm2
	UID  uint32
	GID  uint32
	Node string // the daemon's node binary (/proc/<pid>/exe)
}

// pm2Process is one entry of `pm2 jlist`.
type pm2Process struct {
	Name string `json:"name"`
	PM2  struct {
		Status     string `json:"status"`
		PMUptime   int64  `json:"pm_uptime"`
		Restarts   int    `json:"restart_time"`
		ErrLogPath string `json:"pm_err_log_path"`
		Cwd        string `json:"pm_cwd"`
	} `json:"pm2_env"`
	Monit struct {
		Memory uint64  `json:"memory"`
		CPU    float64 `json:"cpu"`
	} `json:"monit"`

	// Filled in by us, not by PM2.
	User string `json:"-"`
	Home string `json:"-"`
}

var pm2DaemonTitleRe = regexp.MustCompile(`^PM2 v[^:]*: God Daemon \((/[^)]*)\)`)

// parsePM2DaemonTitle returns PM2_HOME from a daemon's process title.
func parsePM2DaemonTitle(cmdline string) (string, bool) {
	cmdline = strings.TrimSpace(strings.ReplaceAll(cmdline, "\x00", " "))
	m := pm2DaemonTitleRe.FindStringSubmatch(cmdline)
	if m == nil {
		return "", false
	}
	return filepath.Clean(m[1]), true
}

// findPM2Daemons scans /proc for PM2 God Daemons. Cheap: one small read per pid.
func findPM2Daemons() []pm2Daemon {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []pm2Daemon
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		base := filepath.Join("/proc", e.Name())
		cmd, err := os.ReadFile(filepath.Join(base, "cmdline"))
		if err != nil || !bytes.HasPrefix(cmd, []byte("PM2 v")) {
			continue
		}
		home, ok := parsePM2DaemonTitle(string(cmd))
		if !ok {
			continue
		}
		uid, gid, ok := procOwner(base)
		if !ok {
			continue
		}
		node, _ := os.Readlink(filepath.Join(base, "exe"))
		out = append(out, pm2Daemon{PID: pid, Home: home, UID: uid, GID: gid, Node: node})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Home < out[j].Home })
	return out
}

// procOwner reads the real uid/gid from /proc/<pid>/status.
func procOwner(base string) (uint32, uint32, bool) {
	data, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return 0, 0, false
	}
	return parseProcOwner(string(data))
}

func parseProcOwner(status string) (uint32, uint32, bool) {
	var uid, gid uint64
	var haveU, haveG bool
	for _, line := range strings.Split(status, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "Uid:":
			if v, err := strconv.ParseUint(f[1], 10, 32); err == nil {
				uid, haveU = v, true
			}
		case "Gid:":
			if v, err := strconv.ParseUint(f[1], 10, 32); err == nil {
				gid, haveG = v, true
			}
		}
	}
	return uint32(uid), uint32(gid), haveU && haveG
}

// pm2CLICandidates lists where the pm2 CLI that belongs to a daemon may live,
// most likely first: next to the daemon's node (nvm and most npm prefixes put
// both in the same bin/), the owner's ~/.npm-global, then system paths.
func pm2CLICandidates(node, userHome string) []string {
	var c []string
	if node != "" {
		c = append(c, filepath.Join(filepath.Dir(node), "pm2"))
	}
	if userHome != "" {
		c = append(c, filepath.Join(userHome, ".npm-global", "bin", "pm2"))
	}
	return append(c, "/usr/local/bin/pm2", "/usr/bin/pm2", "/opt/nodejs/bin/pm2")
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

const pm2QueryTimeout = 10 * time.Second

// queryPM2Daemon runs `pm2 jlist` against one daemon as its owner.
func queryPM2Daemon(ctx context.Context, d pm2Daemon) ([]pm2Process, error) {
	if _, err := os.Stat(filepath.Join(d.Home, "rpc.sock")); err != nil {
		return nil, err // no socket → the CLI would spawn a NEW daemon; never do that
	}
	username, userHome := "", ""
	if u, err := user.LookupId(strconv.FormatUint(uint64(d.UID), 10)); err == nil {
		username, userHome = u.Username, u.HomeDir
	}
	cli := firstExisting(pm2CLICandidates(d.Node, userHome))
	if cli == "" {
		return nil, os.ErrNotExist
	}
	// /proc/<pid>/exe can be unreadable (no CAP_SYS_PTRACE, e.g. in a
	// container); then use the node that sits next to the CLI, or the system one.
	node := d.Node
	if node == "" {
		node = firstExisting([]string{filepath.Join(filepath.Dir(cli), "node"), "/usr/local/bin/node", "/usr/bin/node"})
	}
	if node == "" {
		return nil, os.ErrNotExist
	}

	cctx, cancel := context.WithTimeout(ctx, pm2QueryTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, node, cli, "jlist")
	if userHome == "" {
		userHome = filepath.Dir(d.Home)
	}
	cmd.Dir = userHome
	cmd.Env = []string{
		"PM2_HOME=" + d.Home,
		"HOME=" + userHome,
		"PATH=" + filepath.Dir(node) + ":" + filepath.Dir(cli) + ":/usr/local/bin:/usr/bin:/bin",
	}
	if d.UID != uint32(os.Geteuid()) {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: d.UID, Gid: d.GID}}
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	procs, err := parsePM2JList(stdout.Bytes())
	if err != nil {
		return nil, err
	}
	for i := range procs {
		procs[i].User = username
		procs[i].Home = d.Home
	}
	return procs, nil
}

// parsePM2JList parses `pm2 jlist`, skipping any banner/warning printed before
// the JSON array (e.g. "In-memory PM2 is out-of-date").
func parsePM2JList(out []byte) ([]pm2Process, error) {
	if i := bytes.IndexByte(out, '['); i > 0 {
		out = out[i:]
	}
	var procs []pm2Process
	if err := json.Unmarshal(out, &procs); err != nil {
		return nil, err
	}
	return procs, nil
}

var (
	pm2CacheMu sync.Mutex
	pm2CacheAt time.Time
	pm2Cache   []pm2Process
)

// sharedPM2Apps returns every PM2 app on the box, from every daemon. Shared
// by the services and logs collectors; refreshed at most every 30 s (< the
// heartbeat) so one heartbeat runs each daemon's CLI once.
func sharedPM2Apps(ctx context.Context) []pm2Process {
	pm2CacheMu.Lock()
	defer pm2CacheMu.Unlock()
	if time.Since(pm2CacheAt) < 30*time.Second {
		return pm2Cache
	}
	var apps []pm2Process
	daemons := findPM2Daemons()
	for _, d := range daemons {
		if procs, err := queryPM2Daemon(ctx, d); err == nil {
			apps = append(apps, procs...)
		}
	}
	// Old behaviour as a last resort: a root-owned pm2 on PATH whose daemon
	// we did not see (e.g. hidepid on /proc).
	if len(daemons) == 0 && hasBinary("pm2") {
		if out, err := runCmdTimeout(ctx, pm2QueryTimeout, "pm2", "jlist"); err == nil {
			if procs, err := parsePM2JList(out); err == nil {
				apps = procs
			}
		}
	}
	pm2Cache, pm2CacheAt = apps, time.Now()
	return apps
}

// pm2LogFile is one PM2 error log and the app that writes it.
type pm2LogFile struct {
	Path string
	App  string
}

// pm2ErrorLogFiles lists PM2 error logs: the exact path each app reports
// (pm_err_log_path), plus — for daemons we could not query — the default
// files in <PM2_HOME>/logs, which PM2 names "<app>-error.log" ("<app>-error-<id>.log" in cluster mode).
func pm2ErrorLogFiles(ctx context.Context) []pm2LogFile {
	seen := map[string]bool{}
	var out []pm2LogFile
	add := func(path, app string) {
		if path == "" || seen[path] || app == "" {
			return
		}
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return
		}
		seen[path] = true
		out = append(out, pm2LogFile{Path: path, App: app})
	}
	queried := map[string]bool{}
	for _, a := range sharedPM2Apps(ctx) {
		queried[a.Home] = true
		add(a.PM2.ErrLogPath, a.Name)
	}
	homes := []string{}
	for _, d := range findPM2Daemons() {
		if !queried[d.Home] {
			homes = append(homes, d.Home)
		}
	}
	if len(homes) == 0 && len(queried) == 0 {
		if h, err := os.UserHomeDir(); err == nil {
			homes = append(homes, filepath.Join(h, ".pm2"))
		}
	}
	for _, home := range homes {
		matches, _ := filepath.Glob(filepath.Join(home, "logs", "*error*.log"))
		for _, m := range matches {
			add(m, pm2AppFromLogName(filepath.Base(m)))
		}
	}
	return out
}

var pm2ErrLogNameRe = regexp.MustCompile(`^(.+?)[-.]error(?:-\d+)?\.log$`)

// pm2AppFromLogName maps "api-error.log", "api-error-3.log" or the legacy
// "api.error.log" to "api".
func pm2AppFromLogName(name string) string {
	if m := pm2ErrLogNameRe.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return ""
}
