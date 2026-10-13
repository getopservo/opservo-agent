package collectors

import "testing"

func TestParseSupervisorStatus(t *testing.T) {
	out := []byte(`laravel-worker:laravel-worker_00   RUNNING   pid 1234, uptime 2 days, 3:04:05
laravel-worker:laravel-worker_01   FATAL     Exited too quickly (process log may have details)
horizon                            BACKOFF   Exited too quickly (process log may have details)
scheduler                          EXITED    Oct 12 10:00 AM
reports                            STOPPED   Not started
`)
	got, running := parseSupervisorStatus(out, false)
	if running == nil || !*running {
		t.Fatalf("running = %v, want true", running)
	}
	if len(got) != 5 {
		t.Fatalf("got %d programs, want 5", len(got))
	}
	want := []struct{ name, status, state, uptime, desc string }{
		{"laravel-worker:laravel-worker_00", "running", "RUNNING", "2 days, 3:04:05", ""},
		{"laravel-worker:laravel-worker_01", "failed", "FATAL", "", "Exited too quickly (process log may have details)"},
		{"horizon", "restarting", "BACKOFF", "", "Exited too quickly (process log may have details)"},
		{"scheduler", "exited", "EXITED", "", "Oct 12 10:00 AM"},
		{"reports", "stopped", "STOPPED", "", "Not started"},
	}
	for i, w := range want {
		g := got[i]
		if g.Name != w.name || g.Type != "supervisor" || g.Status != w.status || g.SupervisorState != w.state || g.Uptime != w.uptime || g.Description != w.desc {
			t.Errorf("program %d = %+v, want %+v", i, g, w)
		}
	}
}

func TestParseSupervisorStatusDaemonDown(t *testing.T) {
	for _, out := range []string{
		"unix:///var/run/supervisor.sock no such file\n",
		"unix:///run/supervisor.sock refused connection\n",
		"error: <class 'xmlrpclib.Fault'>, <Fault 6: 'SHUTDOWN_STATE'>\n",
	} {
		got, running := parseSupervisorStatus([]byte(out), false)
		if len(got) != 0 || running == nil || *running {
			t.Errorf("%q: got %d programs, running=%v; want 0, false", out, len(got), running)
		}
	}
}

func TestParseSupervisorStatusUnclear(t *testing.T) {
	// Up with no programs: empty output, exit 0.
	if got, running := parseSupervisorStatus(nil, true); len(got) != 0 || running == nil || !*running {
		t.Errorf("empty listing: running=%v, want true", running)
	}
	// Permission denied etc.: we can't tell, so say nothing.
	if _, running := parseSupervisorStatus([]byte("error: <class 'PermissionError'>, [Errno 13] Permission denied\n"), false); running != nil {
		t.Errorf("permission denied: running=%v, want nil", *running)
	}
}
