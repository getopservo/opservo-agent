package collectors

import (
	"testing"
	"time"
)

func TestParseSystemdShowBlocks(t *testing.T) {
	out := "Id=certbot.service\nType=oneshot\nTriggeredBy=certbot.timer\nResult=exit-code\nExecMainStatus=1\nExecMainExitTimestampMonotonic=3600000000\nActiveState=failed\n\n" +
		"Id=nginx.service\nType=forking\nTriggeredBy=\nResult=signal\nExecMainStatus=9\nExecMainExitTimestampMonotonic=0\nActiveState=failed\n"
	got := parseSystemdShowBlocks(out)
	if len(got) != 2 || got["certbot.service"]["TriggeredBy"] != "certbot.timer" || got["nginx.service"]["Type"] != "forking" {
		t.Fatalf("parsed %+v", got)
	}
}

func TestApplyFailedUnitMeta(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	svc := ServiceInfo{Name: "certbot", Type: "systemd", Status: "failed"}
	// Booted 2 h ago (7200 s up); the run ended 1 h after boot → 1 h ago.
	applyFailedUnitMeta(&svc, map[string]string{
		"Type": "oneshot", "TriggeredBy": "certbot.timer snap.certbot.renew.timer", "Result": "exit-code",
		"ExecMainStatus": "1", "ExecMainExitTimestampMonotonic": "3600000000",
	}, 7200, now)
	if svc.UnitType != "oneshot" || svc.TriggeredBy != "certbot.timer" || svc.LastResult != "exit-code" {
		t.Fatalf("meta = %+v", svc)
	}
	if svc.LastExitStatus == nil || *svc.LastExitStatus != 1 {
		t.Fatalf("exit status = %v", svc.LastExitStatus)
	}
	if svc.LastRunAt != "2026-10-09T11:00:00Z" {
		t.Fatalf("last run = %q, want 2026-10-09T11:00:00Z", svc.LastRunAt)
	}
	if !isScheduledJob(svc) {
		t.Fatal("a timer-started oneshot is a scheduled job")
	}
	daemon := ServiceInfo{Name: "nginx", Type: "systemd", Status: "failed"}
	applyFailedUnitMeta(&daemon, map[string]string{"Type": "forking", "TriggeredBy": "", "ExecMainExitTimestampMonotonic": "0"}, 7200, now)
	if isScheduledJob(daemon) || daemon.LastRunAt != "" {
		t.Fatalf("a forking daemon is not a scheduled job: %+v", daemon)
	}
}

func TestFailedJobStillPending(t *testing.T) {
	if !failedJobStillPending(map[string]string{"ActiveState": "activating"}) {
		t.Fatal("a re-running job keeps its failed last run")
	}
	for _, st := range []string{"inactive", "active", ""} {
		if failedJobStillPending(map[string]string{"ActiveState": st}) {
			t.Fatalf("state %q means the next run finished (or the unit is gone): forget it", st)
		}
	}
}
