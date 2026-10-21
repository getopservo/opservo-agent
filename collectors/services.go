package collectors

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ServiceInfo describes one running (or failed) service unit, container, or
// PM2 process. Fields that a given source cannot provide are left zero.
type ServiceInfo struct {
	Name         string  `json:"name"`
	Type         string  `json:"type"`   // systemd | docker | pm2 | supervisor
	Status       string  `json:"status"` // running | failed | restarting | stopped | <raw>
	Uptime       string  `json:"uptime,omitempty"`
	CPUPercent   float64 `json:"cpu_percent,omitempty"`
	MemoryBytes  uint64  `json:"memory_bytes,omitempty"`
	RestartCount int     `json:"restart_count"`
	Description  string  `json:"description,omitempty"`
	// Owner: the Linux user whose daemon runs this service, when it is not the
	// system one — a rootless Docker container ("alice") or a per-user PM2 app.
	Owner string `json:"owner,omitempty"`

	// Failed systemd units only (see scheduledjobs.go): what kind of unit it
	// is and how its last run ended, so a timer job is judged on its last run.
	UnitType       string `json:"unit_type,omitempty"`        // Type= ("oneshot", "simple", …)
	TriggeredBy    string `json:"triggered_by,omitempty"`     // e.g. "certbot.timer"
	LastResult     string `json:"last_result,omitempty"`      // Result= ("exit-code", "timeout", …)
	LastExitStatus *int   `json:"last_exit_status,omitempty"` // ExecMainStatus of the last run
	LastRunAt      string `json:"last_run_at,omitempty"`      // RFC 3339, when the last run ended
	Rerunning      bool   `json:"rerunning,omitempty"`        // last run failed; the next run is in progress now

	// Supervisor programs only: the raw supervisorctl state (FATAL, BACKOFF,
	// EXITED, …); Status carries the normalised form.
	SupervisorState string `json:"supervisor_state,omitempty"`
}

// ServicesReport is the full output of the service collector. The *_installed
// flags let the optimization engine reason about absence (e.g. docker present
// but no containers running) without re-probing the host.
type ServicesReport struct {
	Services         []ServiceInfo `json:"services"`
	SystemdAvailable bool          `json:"systemd_available"`
	DockerInstalled  bool          `json:"docker_installed"`
	PM2Installed     bool          `json:"pm2_installed"`
	// SupervisorInstalled: supervisorctl is on PATH. SupervisorRunning: whether
	// supervisord answered (nil = could not tell, e.g. permission denied).
	SupervisorInstalled bool      `json:"supervisor_installed"`
	SupervisorRunning   *bool     `json:"supervisor_running,omitempty"`
	CollectedAt         time.Time `json:"collected_at"`
}

// ServiceCollector discovers services from systemd, Docker, PM2 and Supervisor. Every
// source is optional: if a tool is not installed the collector skips it
// without erroring, so the agent runs anywhere with zero configuration.
//
// systemd does not expose a CPU percentage directly — only a monotonic counter
// of CPU nanoseconds used (CPUUsageNSec). The collector keeps the previous
// reading per unit between heartbeats and derives a percentage from the delta,
// so CPU% is empty on the very first heartbeat and populated from the second on.
type ServiceCollector struct {
	mu      sync.Mutex
	prevCPU map[string]cpuSample // unit Id ("nginx.service") -> last reading
	// failedJobs: scheduled jobs (timer/oneshot) whose last completed run
	// failed, by unit name — kept while their next run is in progress.
	failedJobs map[string]ServiceInfo
}

// cpuSample is one reading of a unit's cumulative CPU time at a wall-clock instant.
type cpuSample struct {
	usageNSec uint64
	at        time.Time
}

func NewServiceCollector() *ServiceCollector {
	return &ServiceCollector{prevCPU: map[string]cpuSample{}}
}
func (s *ServiceCollector) Name() string { return "services" }

func (s *ServiceCollector) Collect(ctx context.Context) (interface{}, error) {
	report := &ServicesReport{
		Services:    []ServiceInfo{},
		CollectedAt: time.Now().UTC(),
	}

	if hasBinary("systemctl") {
		report.SystemdAvailable = true
		report.Services = append(report.Services, s.collectSystemd(ctx)...)
	}
	if hasBinary("docker") {
		report.DockerInstalled = true
		report.Services = append(report.Services, collectDocker(ctx)...)
	}
	// Rootless daemons run by login users are invisible to the root daemon;
	// discovered by their socket, queried as their owner (rootless.go).
	if rootless := collectRootlessDocker(ctx); len(rootless) > 0 {
		report.DockerInstalled = true
		report.Services = append(report.Services, rootless...)
	}
	// PM2 is found by its daemon process, not by `pm2` on root's PATH: most
	// installs are per-user (nvm, ~/.npm-global) and invisible to root.
	if len(findPM2Daemons()) > 0 || hasBinary("pm2") {
		report.PM2Installed = true
		report.Services = append(report.Services, collectPM2(ctx)...)
	}
	if hasBinary("supervisorctl") {
		report.SupervisorInstalled = true
		programs, running := collectSupervisor(ctx)
		report.Services = append(report.Services, programs...)
		report.SupervisorRunning = running
	}

	return report, nil
}

// hasBinary reports whether a command is available on PATH.
func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// defaultCmdTimeout bounds any collector command whose context carries no
// deadline of its own, so a wedged `docker ps` / `journalctl` can never hold
// a heartbeat open (the registry's per-collector deadline is the outer bound).
const defaultCmdTimeout = 15 * time.Second

// runCmd executes a command with the collector context and returns stdout.
// stderr is discarded; a non-zero exit returns the error so callers can skip.
func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	return runCmdEnv(ctx, nil, name, args...)
}

// Output caps for commands whose size depends on what other software prints.
const (
	maxDockerLogBytes = 1 << 20 // per container, per heartbeat
	maxWebLogBytes    = 4 << 20 // 8000 access-log lines ≈ 1.5 MB; leaves room
)

// tailBuffer keeps only the LAST max bytes written (the newest log lines),
// so memory stays bounded whatever the child prints.
type tailBuffer struct {
	max       int
	buf       []byte
	truncated bool
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2*t.max { // trim in batches, not on every write
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-t.max:]...)
		t.truncated = true
	}
	return n, nil
}

// Bytes returns at most max bytes; when output was cut, the leading partial
// line is dropped so callers only ever see whole lines.
func (t *tailBuffer) Bytes() []byte {
	b := t.buf
	if len(b) > t.max {
		b = b[len(b)-t.max:]
		t.truncated = true
	}
	if t.truncated {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return b
}

// runCmdTail is runCmdTimeout with stdout bounded to its last max bytes.
func runCmdTail(ctx context.Context, timeout time.Duration, max int, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tb := &tailBuffer{max: max}
	if err := runCmdInto(ctx, nil, tb, name, args...); err != nil {
		return nil, err
	}
	return tb.Bytes(), nil
}

// runCmdEnv is runCmd with extra environment variables for the child only
// (e.g. libpq PG* connection settings, which must never appear in argv).
// The command runs in its own process group and the WHOLE group is killed when
// the context ends, so a child that outlives `sh -c` cannot keep the stdout
// pipe open and block Wait; WaitDelay is the backstop for I/O copying.
func runCmdEnv(ctx context.Context, extraEnv []string, name string, args ...string) ([]byte, error) {
	var out bytes.Buffer
	if err := runCmdInto(ctx, extraEnv, &out, name, args...); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// runCmdInto runs a command like runCmdEnv but streams stdout into w.
func runCmdInto(ctx context.Context, extraEnv []string, w io.Writer, name string, args ...string) error {
	return runCmdIntoAs(ctx, nil, extraEnv, w, name, args...)
}

// runCmdIntoAs is runCmdInto with an optional identity: when cred is set the
// child runs as that uid/gid (the agent runs as root) with ONLY env as its
// environment — nothing of the agent's own environment leaks to another
// user's process. Used for per-user daemons (rootless Docker).
func runCmdIntoAs(ctx context.Context, cred *syscall.Credential, env []string, w io.Writer, name string, args ...string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCmdTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	if cred != nil {
		cmd.Env = env
	} else if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: cred}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdout = w
	return cmd.Run()
}

// ── systemd ────────────────────────────────────────────────────────────────

func (s *ServiceCollector) collectSystemd(ctx context.Context) []ServiceInfo {
	var services []ServiceInfo
	services = append(services, listSystemdUnits(ctx, "running", "running")...)
	services = append(services, listSystemdUnits(ctx, "failed", "failed")...)
	s.enrichSystemd(ctx, services)
	return s.enrichFailedUnits(ctx, services)
}

// enrichSystemd fills MemoryBytes and CPUPercent per running unit from its
// cgroup accounting (MemoryCurrent + CPUUsageNSec), in a single batched
// `systemctl show`. CPU% is derived from the change in CPUUsageNSec since the
// previous heartbeat (percent of one core), so it is 0 until a second reading.
func (s *ServiceCollector) enrichSystemd(ctx context.Context, services []ServiceInfo) {
	idx := map[string]int{}
	var units []string
	for i := range services {
		if services[i].Type == "systemd" && services[i].Status == "running" {
			id := services[i].Name + ".service"
			idx[id] = i
			units = append(units, id)
		}
	}
	if len(units) == 0 {
		return
	}
	args := append([]string{"show", "-p", "Id", "-p", "MemoryCurrent", "-p", "CPUUsageNSec"}, units...)
	out, err := runCmd(ctx, "systemctl", args...)
	if err != nil {
		return
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]cpuSample, len(units))

	// Output is one block per unit, blocks separated by a blank line.
	var id string
	var mem, cpuNSec uint64
	var haveCPU bool
	flush := func() {
		if id != "" {
			if i, ok := idx[id]; ok {
				if mem > 0 {
					services[i].MemoryBytes = mem
				}
				if haveCPU {
					cur := cpuSample{usageNSec: cpuNSec, at: now}
					next[id] = cur
					if prev, ok := s.prevCPU[id]; ok {
						services[i].CPUPercent = cpuPercentFromDelta(prev, cur)
					}
				}
			}
		}
		id, mem, cpuNSec, haveCPU = "", 0, 0, false
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Id="):
			id = strings.TrimPrefix(line, "Id=")
		case strings.HasPrefix(line, "MemoryCurrent="):
			v := strings.TrimPrefix(line, "MemoryCurrent=")
			// "[not set]" / uint64-max mean unaccounted.
			if n, err := strconv.ParseUint(v, 10, 64); err == nil && n != ^uint64(0) {
				mem = n
			}
		case strings.HasPrefix(line, "CPUUsageNSec="):
			v := strings.TrimPrefix(line, "CPUUsageNSec=")
			// "[not set]" means CPU accounting is off for this unit.
			if n, err := strconv.ParseUint(v, 10, 64); err == nil && n != ^uint64(0) {
				cpuNSec, haveCPU = n, true
			}
		}
	}
	flush()

	// Replace the previous-sample map so units that stopped don't leak memory.
	s.prevCPU = next
}

// cpuPercentFromDelta converts the change in cumulative CPU nanoseconds between
// two samples into a percentage of one CPU core, rounded to one decimal. A
// counter reset (cur < prev) or non-positive interval yields 0.
func cpuPercentFromDelta(prev, cur cpuSample) float64 {
	dWall := cur.at.Sub(prev.at).Nanoseconds()
	if dWall <= 0 || cur.usageNSec < prev.usageNSec {
		return 0
	}
	pct := float64(cur.usageNSec-prev.usageNSec) / float64(dWall) * 100
	if pct < 0 {
		pct = 0
	}
	return float64(int(pct*10+0.5)) / 10
}

// listSystemdUnits parses `systemctl list-units` for one state. The output is
// columnar (UNIT LOAD ACTIVE SUB DESCRIPTION); we treat any line whose first
// field ends in ".service" as a unit, which skips the header and summary lines
// regardless of locale or legend settings.
func listSystemdUnits(ctx context.Context, state, status string) []ServiceInfo {
	out, err := runCmd(ctx, "systemctl",
		"list-units", "--type=service", "--state="+state, "--no-pager", "--plain")
	if err != nil {
		return nil
	}
	return parseSystemdUnits(out, status)
}

// parseSystemdUnits extracts service units from `systemctl list-units` output.
// Any line whose first field ends in ".service" is treated as a unit, which
// skips header and summary lines regardless of locale or legend settings.
func parseSystemdUnits(out []byte, status string) []ServiceInfo {
	var services []ServiceInfo
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".service")
		desc := ""
		if len(fields) > 4 {
			desc = strings.Join(fields[4:], " ")
		}
		services = append(services, ServiceInfo{
			Name:        name,
			Type:        "systemd",
			Status:      status,
			Description: desc,
		})
	}
	return services
}

// ── Docker ───────────────────────────────────────────────────────────────────

type dockerPSLine struct {
	ID     string `json:"ID"`
	Names  string `json:"Names"`
	Image  string `json:"Image"`
	State  string `json:"State"`
	Status string `json:"Status"`
}

func collectDocker(ctx context.Context) []ServiceInfo {
	out, err := runCmd(ctx, "docker", "ps", "--format", "json")
	if err != nil {
		return nil
	}
	services, ids := parseDockerPSJSON(out)

	// RestartCount is not exposed by `docker ps`; fetch it in one inspect call.
	applyRestartCounts(services, dockerRestartCounts(ctx, ids))

	// Live CPU% + memory per container, in one `docker stats` call.
	applyContainerStats(services, dockerStats(ctx))
	return services
}

// parseDockerPSJSON turns `docker ps --format json` (one object per line) into
// docker ServiceInfo rows plus the container ids, for the inspect call.
func parseDockerPSJSON(out []byte) ([]ServiceInfo, []string) {
	var services []ServiceInfo
	var ids []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var c dockerPSLine
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}
		status := c.State
		if status == "" {
			status = "running"
		}
		services = append(services, ServiceInfo{
			Name:        c.Names,
			Type:        "docker",
			Status:      status,
			Uptime:      c.Status,
			Description: c.Image,
		})
		if c.ID != "" {
			ids = append(ids, c.ID)
		}
	}
	return services, ids
}

func applyRestartCounts(services []ServiceInfo, restarts map[string]int) {
	for i := range services {
		if rc, ok := restarts[services[i].Name]; ok {
			services[i].RestartCount = rc
		}
	}
}

func applyContainerStats(services []ServiceInfo, stats map[string]containerStat) {
	for i := range services {
		if s, ok := stats[services[i].Name]; ok {
			services[i].CPUPercent = s.cpu
			services[i].MemoryBytes = s.mem
		}
	}
}

type containerStat struct {
	cpu float64
	mem uint64
}

// dockerStats returns CPU% + memory bytes per container name from a single
// non-streaming `docker stats` call.
func dockerStats(ctx context.Context) map[string]containerStat {
	// Shared with the containers collector so `docker stats` runs once per cycle
	//. The output has extra columns (Mem%, NetIO) which we ignore here.
	out, err := sharedDockerStats(ctx)
	if err != nil {
		return nil
	}
	return parseDockerStatsBrief(out)
}

// parseDockerStatsBrief reads Name\tCPU%\tMemUsage rows into CPU% + used bytes.
func parseDockerStatsBrief(out []byte) map[string]containerStat {
	stats := make(map[string]containerStat)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 3 {
			continue
		}
		cpu, _ := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(parts[1]), "%"), 64)
		// MemUsage is "123.4MiB / 2GiB" — take the used part.
		used := strings.TrimSpace(strings.SplitN(parts[2], "/", 2)[0])
		stats[strings.TrimSpace(parts[0])] = containerStat{cpu: cpu, mem: parseHumanBytes(used)}
	}
	return stats
}

// parseHumanBytes converts docker's "123.4MiB" / "2GiB" / "512kB" to bytes.
func parseHumanBytes(s string) uint64 {
	s = strings.TrimSpace(s)
	mult := map[string]float64{
		"B": 1, "kB": 1e3, "KB": 1e3, "KiB": 1 << 10, "MB": 1e6, "MiB": 1 << 20,
		"GB": 1e9, "GiB": 1 << 30, "TB": 1e12, "TiB": 1 << 40,
	}
	// Find where the number ends.
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	num, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0
	}
	unit := strings.TrimSpace(s[i:])
	if m, ok := mult[unit]; ok {
		return uint64(num * m)
	}
	return uint64(num)
}

// dockerRestartCounts returns a map of container name -> restart count.
func dockerRestartCounts(ctx context.Context, ids []string) map[string]int {
	if len(ids) == 0 {
		return nil
	}
	args := append([]string{"inspect", "--format", "{{.Name}}|{{.RestartCount}}"}, ids...)
	out, err := runCmd(ctx, "docker", args...)
	if err != nil {
		return nil
	}
	return parseRestartCounts(out)
}

func parseRestartCounts(out []byte) map[string]int {
	counts := make(map[string]int)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "|", 2)
		if len(parts) != 2 {
			continue
		}
		// docker prepends "/" to inspected names.
		name := strings.TrimPrefix(strings.TrimSpace(parts[0]), "/")
		if rc, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
			counts[name] = rc
		}
	}
	return counts
}

// ── PM2 ──────────────────────────────────────────────────────────────────────
// Discovery and querying live in pm2.go.

func collectPM2(ctx context.Context) []ServiceInfo {
	var services []ServiceInfo
	for _, a := range sharedPM2Apps(ctx) {
		svc := ServiceInfo{
			Name:         a.Name,
			Type:         "pm2",
			Status:       a.PM2.Status,
			CPUPercent:   a.Monit.CPU,
			MemoryBytes:  a.Monit.Memory,
			RestartCount: a.PM2.Restarts,
		}
		if a.User != "" {
			svc.Description = "PM2 app run by " + a.User
			svc.Owner = a.User
		}
		services = append(services, svc)
	}
	return services
}
