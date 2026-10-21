package collectors

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Rootless Docker discovery (backlog B-9, 19 Oct 2026).
//
// A rootless daemon (`dockerd-rootless-setuptool.sh install`) belongs to one
// login user and listens on that user's own socket, so the root daemon's
// `docker ps` never sees its containers. Mirrors the per-user PM2 discovery:
// find each daemon by its socket, query it AS ITS OWNER (never as root, which
// would also fail: the socket is 0600), and tag every container with the
// owning user so the dashboard can say "run by alice".
//
// Opt-out: OPSERVO_SKIP_ROOTLESS_DOCKER=true in /etc/infrapilot/config.

const rootlessSkipEnv = "OPSERVO_SKIP_ROOTLESS_DOCKER"

// rootlessDaemon is one running rootless Docker daemon and its owner.
type rootlessDaemon struct {
	UID, GID uint32
	User     string // login name
	Home     string
	Socket   string // unix socket path
}

// rootlessSocketCandidates lists where a user's rootless daemon may listen:
// $XDG_RUNTIME_DIR/docker.sock (the default) or ~/.docker/run/docker.sock
// (used when the runtime dir is unavailable, e.g. no systemd user session).
func rootlessSocketCandidates(uid uint32, home string) []string {
	out := []string{filepath.Join("/run/user", strconv.FormatUint(uint64(uid), 10), "docker.sock")}
	if home != "" {
		out = append(out, filepath.Join(home, ".docker", "run", "docker.sock"))
	}
	return out
}

// isSocket reports whether path exists and is a unix socket.
func isSocket(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// findRootlessDockerDaemons scans /run/user for login users (uid >= 1000)
// whose rootless daemon socket exists. Cheap: a few stats per heartbeat.
func findRootlessDockerDaemons() []rootlessDaemon {
	if os.Getenv(rootlessSkipEnv) == "true" || os.Getenv(rootlessSkipEnv) == "1" {
		return nil
	}
	entries, err := os.ReadDir("/run/user")
	if err != nil {
		return nil
	}
	var out []rootlessDaemon
	for _, e := range entries {
		uid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil || !e.IsDir() || uid < 1000 {
			continue // system accounts never run a rootless daemon we would report
		}
		u, err := user.LookupId(e.Name())
		if err != nil {
			continue
		}
		gid, _ := strconv.ParseUint(u.Gid, 10, 32)
		for _, sock := range rootlessSocketCandidates(uint32(uid), u.HomeDir) {
			if isSocket(sock) {
				out = append(out, rootlessDaemon{UID: uint32(uid), GID: uint32(gid), User: u.Username, Home: u.HomeDir, Socket: sock})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// sharedRootlessDaemons is findRootlessDockerDaemons once per heartbeat,
// shared by the services, containers and logs collectors.
func sharedRootlessDaemons(ctx context.Context) []rootlessDaemon {
	if !hasBinary("docker") && !rootlessCLIExists() {
		return nil
	}
	out, err := cachedRun("rootless-daemons", 30*time.Second, func() ([]byte, error) {
		var b bytes.Buffer
		for _, d := range findRootlessDockerDaemons() {
			b.WriteString(strconv.FormatUint(uint64(d.UID), 10) + "\t" + strconv.FormatUint(uint64(d.GID), 10) + "\t" + d.User + "\t" + d.Home + "\t" + d.Socket + "\n")
		}
		return b.Bytes(), nil
	})
	if err != nil {
		return nil
	}
	return parseRootlessDaemons(string(out))
}

func parseRootlessDaemons(s string) []rootlessDaemon {
	var out []rootlessDaemon
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			continue
		}
		uid, _ := strconv.ParseUint(f[0], 10, 32)
		gid, _ := strconv.ParseUint(f[1], 10, 32)
		out = append(out, rootlessDaemon{UID: uint32(uid), GID: uint32(gid), User: f[2], Home: f[3], Socket: f[4]})
	}
	return out
}

func rootlessCLIExists() bool {
	for _, d := range findRootlessDockerDaemons() {
		if d.cli() != "" {
			return true
		}
	}
	return false
}

// cli finds the docker CLI for this daemon: the system one, else the one the
// rootless installer puts in ~/bin or ~/.docker/bin.
func (d rootlessDaemon) cli() string {
	if p, err := exec.LookPath("docker"); err == nil {
		return p
	}
	return firstExisting([]string{filepath.Join(d.Home, "bin", "docker"), filepath.Join(d.Home, ".docker", "bin", "docker")})
}

// env is the ONLY environment the per-user docker CLI gets: its socket, its
// home (for ~/.docker/config.json) and a plain PATH.
func (d rootlessDaemon) env() []string {
	return []string{
		"DOCKER_HOST=unix://" + d.Socket,
		"HOME=" + d.Home,
		"XDG_RUNTIME_DIR=" + filepath.Join("/run/user", strconv.FormatUint(uint64(d.UID), 10)),
		"PATH=" + filepath.Join(d.Home, "bin") + ":/usr/local/bin:/usr/bin:/bin",
	}
}

func (d rootlessDaemon) cred() *syscall.Credential {
	if d.UID == uint32(os.Geteuid()) {
		return nil
	}
	return &syscall.Credential{Uid: d.UID, Gid: d.GID, NoSetGroups: true}
}

// run executes `docker <args>` against this daemon as its owner, cached for
// the heartbeat (the services, containers and logs collectors share one
// `ps` and one `stats` per daemon, like the root daemon's cachedCmd).
func (d rootlessDaemon) run(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	cli := d.cli()
	if cli == "" {
		return nil, exec.ErrNotFound
	}
	key := "rootless\x00" + d.Socket + "\x00" + strings.Join(args, "\x00")
	return cachedRun(key, 30*time.Second, func() ([]byte, error) {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var out bytes.Buffer
		if err := runCmdIntoAs(cctx, d.cred(), d.env(), &out, cli, args...); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	})
}

func (d rootlessDaemon) stats(ctx context.Context) ([]byte, error) {
	return d.run(ctx, 8*time.Second, "stats", "--no-stream", "--no-trunc",
		"--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}")
}

// containers lists this daemon's running containers (name + image).
func (d rootlessDaemon) containers(ctx context.Context) []containerRef {
	out, err := d.run(ctx, 4*time.Second, "ps", "--format", "{{.Names}}\t{{.Image}}")
	if err != nil {
		return nil
	}
	return parseContainerRefs(string(out))
}

// logTail is the capped `docker logs` tail for one container, as the owner.
func (d rootlessDaemon) logTail(ctx context.Context, name string) ([]byte, error) {
	cli := d.cli()
	if cli == "" {
		return nil, exec.ErrNotFound
	}
	cctx, cancel := context.WithTimeout(ctx, defaultCmdTimeout)
	defer cancel()
	tb := &tailBuffer{max: maxDockerLogBytes}
	if err := runCmdIntoAs(cctx, d.cred(), d.env(), tb, cli, "logs", "--tail", "200", "--since", "1h", "--timestamps", name); err != nil {
		return nil, err
	}
	return tb.Bytes(), nil
}

// collectRootlessDocker returns one docker ServiceInfo per container of every
// rootless daemon, tagged with its owner.
func collectRootlessDocker(ctx context.Context) []ServiceInfo {
	var all []ServiceInfo
	for _, d := range sharedRootlessDaemons(ctx) {
		out, err := d.run(ctx, 8*time.Second, "ps", "--format", "json")
		if err != nil {
			continue
		}
		services, ids := parseDockerPSJSON(out)
		if len(ids) > 0 {
			args := append([]string{"inspect", "--format", "{{.Name}}|{{.RestartCount}}"}, ids...)
			if insp, err := d.run(ctx, 8*time.Second, args...); err == nil {
				applyRestartCounts(services, parseRestartCounts(insp))
			}
		}
		if st, err := d.stats(ctx); err == nil {
			applyContainerStats(services, parseDockerStatsBrief(st))
		}
		for i := range services {
			services[i].Owner = d.User
			services[i].Description = strings.TrimSpace(services[i].Description + " · rootless, run by " + d.User)
		}
		all = append(all, services...)
	}
	return all
}
