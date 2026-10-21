package collectors

import "testing"

// The agent's own process must survive the top-N cut (the public
// agent-overhead benchmark reads it from this list on every server).
func TestTopProcessesKeepsSelf(t *testing.T) {
	var procs []ProcessInfo
	for i := 1; i <= 50; i++ {
		procs = append(procs, ProcessInfo{PID: int32(i), Name: "busy", CPU: float64(100 - i), MemMB: 10})
	}
	procs = append(procs, ProcessInfo{PID: 999, Name: "infrapilot-agent", CPU: 0.1, MemMB: 28})

	got := topProcesses(procs, 999, 40)
	if len(got) != 41 {
		t.Fatalf("want 40 top + self = 41, got %d", len(got))
	}
	if got[40].PID != 999 || got[0].PID != 1 {
		t.Fatalf("self must be appended after the top 40: first %d, last %d", got[0].PID, got[40].PID)
	}

	// Already in the top N: no duplicate.
	got = topProcesses(procs, 1, 40)
	if len(got) != 40 {
		t.Fatalf("self already in the top N: want 40, got %d", len(got))
	}

	// Under the cap: untouched.
	if n := len(topProcesses(procs[:5], 999, 40)); n != 5 {
		t.Fatalf("under the cap: want 5, got %d", n)
	}
}
