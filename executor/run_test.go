package executor

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunCommand_Success(t *testing.T) {
	res := runCommand(context.Background(), "echo hello", nil, 5*time.Second)
	if res.Status != "done" || res.ExitCode != 0 {
		t.Fatalf("expected done/0, got %+v", res)
	}
	if strings.TrimSpace(res.Stdout) != "hello" {
		t.Errorf("stdout = %q", res.Stdout)
	}
}

func TestRunCommand_NonZeroExit(t *testing.T) {
	// A command that runs but exits non-zero is still a "done" result.
	res := runCommand(context.Background(), "echo oops 1>&2; exit 3", nil, 5*time.Second)
	if res.Status != "done" {
		t.Errorf("status = %q, want done", res.Status)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit = %d, want 3", res.ExitCode)
	}
	if !strings.Contains(res.Stderr, "oops") {
		t.Errorf("stderr = %q", res.Stderr)
	}
}

func TestRunCommand_Timeout(t *testing.T) {
	start := time.Now()
	res := runCommand(context.Background(), "sleep 5", nil, 200*time.Millisecond)
	if time.Since(start) > 2*time.Second {
		t.Error("timeout did not interrupt the command promptly")
	}
	if res.Status != "error" {
		t.Errorf("status = %q, want error", res.Status)
	}
}

func TestCapWriter_Truncates(t *testing.T) {
	w := &capWriter{cap: 10}
	w.Write([]byte("0123456789ABCDEF"))
	out := w.String()
	if !strings.HasPrefix(out, "0123456789") {
		t.Errorf("prefix not kept: %q", out)
	}
	if !strings.Contains(out, "truncated") {
		t.Errorf("expected truncation marker, got %q", out)
	}
}

func TestRunCommandWithProgress_StreamsPartialOutput(t *testing.T) {
	var mu sync.Mutex
	var snapshots []string
	res := runCommandWithProgress(context.Background(), "echo one; sleep 0.35; echo two; sleep 0.35; echo three", nil, 5*time.Second, 100*time.Millisecond, func(stdout, _ string) bool {
		mu.Lock()
		snapshots = append(snapshots, stdout)
		mu.Unlock()
		return false
	})
	if res.Status != "done" || res.ExitCode != 0 {
		t.Fatalf("expected done/0, got %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(snapshots) < 2 {
		t.Fatalf("expected at least 2 progress snapshots, got %d: %q", len(snapshots), snapshots)
	}
	// The first snapshot must be a real partial (before "three" was printed) —
	// that's the whole point: output shows up before the command ends.
	if strings.Contains(snapshots[0], "three") {
		t.Errorf("first snapshot already had the final output: %q", snapshots[0])
	}
	if !strings.Contains(snapshots[0], "one") {
		t.Errorf("first snapshot missing early output: %q", snapshots[0])
	}
	// Snapshots are only sent when something changed, so no two are identical.
	for i := 1; i < len(snapshots); i++ {
		if snapshots[i] == snapshots[i-1] {
			t.Errorf("duplicate snapshot %d: %q", i, snapshots[i])
		}
	}
	if !strings.Contains(res.Stdout, "three") {
		t.Errorf("final stdout = %q", res.Stdout)
	}
}

func TestRunCommandWithProgress_NoCallbackForSilentCommand(t *testing.T) {
	calls := 0
	res := runCommandWithProgress(context.Background(), "sleep 0.3", nil, 5*time.Second, 50*time.Millisecond, func(_, _ string) bool { calls++; return false })
	if res.Status != "done" {
		t.Fatalf("got %+v", res)
	}
	if calls != 0 {
		t.Errorf("expected no progress calls for a command with no output, got %d", calls)
	}
}

func TestNextInterval(t *testing.T) {
	base := 5 * time.Second
	cases := []struct {
		hint, want time.Duration
	}{
		{0, base},                                // no hint → default cadence
		{-1, base},                               // garbage → default
		{time.Second, time.Second},               // terminal open → 1 s
		{10 * time.Millisecond, minPollInterval}, // never faster than the floor
		{30 * time.Second, base},                 // API can never slow us below configured
		{base, base},
	}
	for _, c := range cases {
		if got := nextInterval(base, c.hint); got != c.want {
			t.Errorf("nextInterval(%v, %v) = %v, want %v", base, c.hint, got, c.want)
		}
	}
}

func TestRunCommandWithProgress_StopKillsTheProcessGroup(t *testing.T) {
	start := time.Now()
	// `sleep 30` in a child keeps the pipe open; only a process-group kill ends it fast.
	res := runCommandWithProgress(context.Background(), "echo started; sleep 30", nil, 60*time.Second, 50*time.Millisecond, func(stdout, _ string) bool {
		return strings.Contains(stdout, "started")
	})
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("stop took %v — process group was not killed", took)
	}
	if res.Status != "error" || res.ExitCode != -1 || !strings.Contains(res.Stderr, stoppedNote) {
		t.Fatalf("got %+v", res)
	}
	if strings.Contains(res.Stderr, "timeout") {
		t.Errorf("a stop must not be reported as a timeout: %q", res.Stderr)
	}
}

func TestRunCommandWithProgress_KeepaliveReachesASilentCommand(t *testing.T) {
	old := progressKeepalive
	progressKeepalive = 150 * time.Millisecond
	defer func() { progressKeepalive = old }()
	calls := 0
	start := time.Now()
	res := runCommandWithProgress(context.Background(), "sleep 30", nil, 60*time.Second, 50*time.Millisecond, func(_, _ string) bool {
		calls++
		return true // "Stop now" arrives on the first keepalive
	})
	if calls == 0 || time.Since(start) > 5*time.Second {
		t.Fatalf("silent command was not stoppable: calls=%d took=%v", calls, time.Since(start))
	}
	if !strings.Contains(res.Stderr, stoppedNote) {
		t.Fatalf("got %+v", res)
	}
}
