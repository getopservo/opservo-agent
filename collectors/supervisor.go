package collectors

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strings"
)

// ── Supervisor ───────────────────────────────────────────────────────────────
//
// Supervisor (supervisord) is how most Laravel queue workers, Horizon and
// other long-running PHP/Python workers are kept alive. `supervisorctl status`
// lists every program with its state; the agent runs as root, so it can reach
// the control socket. Only names, states and supervisor's own one-line
// description are read — never the program config (which can carry
// `environment=` secrets).

// supervisorStates are the process states supervisorctl prints. A line whose
// second column is not one of these is not a program line (e.g. an error).
var supervisorStates = map[string]string{
	"RUNNING":  "running",
	"STARTING": "starting",
	"BACKOFF":  "restarting",
	"STOPPING": "stopping",
	"STOPPED":  "stopped",
	"EXITED":   "exited",
	"FATAL":    "failed",
	"UNKNOWN":  "unknown",
}

// supervisorDown matches supervisorctl's messages when supervisord itself is
// not running (socket missing, connection refused, or shutting down).
var supervisorDown = regexp.MustCompile(`(?i)no such file|refused connection|connection refused|SHUTDOWN_STATE`)

var supervisorUptime = regexp.MustCompile(`uptime (.+)$`)

// collectSupervisor returns the programs supervisord manages, plus whether
// supervisord answered: true = answered, false = it is not running, nil = we
// could not tell (e.g. permission denied, timeout).
func collectSupervisor(ctx context.Context) ([]ServiceInfo, *bool) {
	cmd := exec.CommandContext(ctx, "supervisorctl", "status")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, nil
	}
	// supervisorctl exits 3 when any program is not RUNNING, so a non-zero
	// exit with program lines is normal; only a missing binary is fatal here.
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return nil, nil
	}
	return parseSupervisorStatus(out, err == nil)
}

// parseSupervisorStatus parses `supervisorctl status` output. exitOK reports
// whether supervisorctl exited 0 (an empty, successful listing means
// supervisord is up with no programs).
func parseSupervisorStatus(out []byte, exitOK bool) ([]ServiceInfo, *bool) {
	var services []ServiceInfo
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		status, ok := supervisorStates[fields[1]]
		if !ok {
			continue
		}
		rest := strings.TrimSpace(strings.Join(fields[2:], " "))
		svc := ServiceInfo{
			Name:            fields[0],
			Type:            "supervisor",
			Status:          status,
			SupervisorState: fields[1],
			Description:     rest,
		}
		if fields[1] == "RUNNING" {
			if m := supervisorUptime.FindStringSubmatch(rest); m != nil {
				svc.Uptime = m[1]
			}
			svc.Description = ""
		}
		services = append(services, svc)
	}

	up := true
	down := false
	switch {
	case len(services) > 0:
		return services, &up
	case supervisorDown.Match(out):
		return nil, &down
	case exitOK && len(bytes.TrimSpace(out)) == 0:
		return nil, &up
	default:
		return nil, nil
	}
}
