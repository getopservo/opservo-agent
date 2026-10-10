package collectors

import (
	"bufio"
	"context"
	"strconv"
	"strings"
	"time"
)

// Failed systemd units: tell daemons from scheduled jobs, and judge a job on
// its LAST COMPLETED RUN (B2.7).
//
// A timer-started or Type=oneshot unit (certbot, clamav-freshclam, a backup
// script) is not "down" between runs — it runs and exits. When its last run
// failed, systemd shows it as failed until the next run starts; while that
// next run is in progress the unit is "activating" and drops out of the failed
// list, so the "Service X is down" finding vanished and came back every few
// minutes. Here:
//   - every failed unit gets its Type=, TriggeredBy=, Result= and exit status
//     (one batched, read-only `systemctl show`), so the API can word it as a
//     scheduled job and judge it on that last result;
//   - a scheduled job whose last run failed keeps being reported as failed
//     (rerunning=true) while its next run is in progress, and is dropped only
//     when a run finishes without failing (or the unit is reset / removed).

// failedUnitProps are the `systemctl show` properties read for failed units.
var failedUnitProps = []string{"Id", "Type", "TriggeredBy", "Result", "ExecMainStatus", "ExecMainExitTimestampMonotonic", "ActiveState"}

// enrichFailedUnits fills scheduled-job metadata on failed systemd units and
// re-adds remembered failed jobs that are re-running right now. Best-effort:
// any systemctl failure leaves the list exactly as listed.
func (s *ServiceCollector) enrichFailedUnits(ctx context.Context, services []ServiceInfo) []ServiceInfo {
	s.mu.Lock()
	if s.failedJobs == nil {
		s.failedJobs = map[string]ServiceInfo{}
	}
	remembered := make(map[string]ServiceInfo, len(s.failedJobs))
	for k, v := range s.failedJobs {
		remembered[k] = v
	}
	s.mu.Unlock()

	listed := map[string]bool{}
	var query []string
	for _, svc := range services {
		if svc.Type != "systemd" {
			continue
		}
		listed[svc.Name] = true
		if svc.Status == "failed" {
			query = append(query, svc.Name+".service")
		}
	}
	// Remembered failed jobs that are no longer listed as failed: are they
	// re-running (keep reporting the failed last run) or did a run succeed?
	for name := range remembered {
		if !listed[name] {
			query = append(query, name+".service")
		}
	}
	if len(query) == 0 {
		return services
	}

	args := []string{"show"}
	for _, p := range failedUnitProps {
		args = append(args, "-p", p)
	}
	out, err := runCmdTimeout(ctx, securityCmdTimeout, "systemctl", append(args, query...)...)
	if err != nil {
		return services
	}
	props := parseSystemdShowBlocks(string(out))
	uptime := readUptimeSeconds()
	now := time.Now().UTC()

	next := map[string]ServiceInfo{}
	for i := range services {
		svc := &services[i]
		if svc.Type != "systemd" || svc.Status != "failed" {
			continue
		}
		p, ok := props[svc.Name+".service"]
		if !ok {
			continue
		}
		applyFailedUnitMeta(svc, p, uptime, now)
		if isScheduledJob(*svc) {
			next[svc.Name] = *svc
		}
	}
	for name, prev := range remembered {
		if listed[name] {
			continue // listed again (failed again, or now a running daemon) — handled above
		}
		p, ok := props[name+".service"]
		if !ok || !failedJobStillPending(p) {
			continue // a run finished without failing, or the unit was reset/removed → forget it
		}
		prev.Rerunning = true
		services = append(services, prev)
		next[name] = prev
	}

	s.mu.Lock()
	s.failedJobs = next
	s.mu.Unlock()
	return services
}

// isScheduledJob reports whether a unit runs-and-exits (timer-started or
// Type=oneshot) rather than being a long-running daemon.
func isScheduledJob(svc ServiceInfo) bool {
	return svc.TriggeredBy != "" || svc.UnitType == "oneshot"
}

// failedJobStillPending: a remembered failed job keeps its finding while its
// next run is in progress ("activating"). Any other state means a run has
// finished without failing, or someone reset the unit.
func failedJobStillPending(p map[string]string) bool {
	return p["ActiveState"] == "activating"
}

// applyFailedUnitMeta copies the scheduled-job facts from `systemctl show`
// properties onto a failed unit. Pure and tested.
func applyFailedUnitMeta(svc *ServiceInfo, p map[string]string, uptimeSec float64, now time.Time) {
	svc.UnitType = p["Type"]
	if tb := strings.TrimSpace(p["TriggeredBy"]); tb != "" {
		svc.TriggeredBy = strings.Fields(tb)[0]
	}
	svc.LastResult = p["Result"]
	if v, err := strconv.Atoi(p["ExecMainStatus"]); err == nil {
		svc.LastExitStatus = &v
	}
	// Monotonic µs since boot → wall clock, via /proc/uptime. Avoids parsing
	// systemd's localized, zone-abbreviated timestamps.
	if mono, err := strconv.ParseFloat(p["ExecMainExitTimestampMonotonic"], 64); err == nil && mono > 0 && uptimeSec > 0 {
		ago := uptimeSec - mono/1e6
		if ago >= 0 {
			svc.LastRunAt = now.Add(-time.Duration(ago * float64(time.Second))).Format(time.RFC3339)
		}
	}
}

// parseSystemdShowBlocks parses multi-unit `systemctl show -p …` output (one
// block per unit, blank-line separated) keyed by Id. Pure and tested.
func parseSystemdShowBlocks(out string) map[string]map[string]string {
	res := map[string]map[string]string{}
	cur := map[string]string{}
	flush := func() {
		if id := cur["Id"]; id != "" {
			res[id] = cur
		}
		cur = map[string]string{}
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[k] = v
		}
	}
	flush()
	return res
}

// readUptimeSeconds returns seconds since boot from /proc/uptime (0 if unknown).
func readUptimeSeconds() float64 {
	f := strings.Fields(readProcFile("/proc/uptime"))
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	return v
}
