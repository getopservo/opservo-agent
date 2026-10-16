package collectors

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeCollector is a Collector whose Collect blocks for `sleep` (or until the
// context ends when honourCtx is set) and then returns data/err.
type fakeCollector struct {
	name      string
	sleep     time.Duration
	honourCtx bool
	data      interface{}
	err       error
}

func (f *fakeCollector) Name() string { return f.name }
func (f *fakeCollector) Collect(ctx context.Context) (interface{}, error) {
	if f.sleep > 0 {
		if f.honourCtx {
			select {
			case <-time.After(f.sleep):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			time.Sleep(f.sleep)
		}
	}
	return f.data, f.err
}

func TestCollectAll_TimedOutCollectorDoesNotBlockHeartbeat(t *testing.T) {
	fast := &fakeCollector{name: "fast", data: map[string]int{"ok": 1}}
	// Ignores its context entirely — the worst case (a wedged exec).
	stuck := &fakeCollector{name: "stuck", sleep: 5 * time.Second}
	failing := &fakeCollector{name: "failing", err: errors.New("boom")}

	reg := NewRegistry([]Collector{fast, stuck, failing})
	reg.PerCollectorTimeout = 200 * time.Millisecond

	start := time.Now()
	payload, err := reg.CollectAll(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CollectAll: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("CollectAll blocked for %s on a stuck collector", elapsed)
	}
	if _, ok := payload.Data["fast"]; !ok {
		t.Fatalf("fast collector's data missing: %+v", payload.Data)
	}
	if got := payload.Errors["stuck"]; got != "timed out after 200ms" {
		t.Fatalf("stuck collector error = %q, want %q", got, "timed out after 200ms")
	}
	if got := payload.Errors["failing"]; got != "boom" {
		t.Fatalf("failing collector error = %q", got)
	}
	if _, ok := payload.Data["stuck"]; ok {
		t.Fatalf("stuck collector must not contribute data")
	}
}

func TestCollectAll_CtxHonouringCollectorReportsDeadline(t *testing.T) {
	polite := &fakeCollector{name: "polite", sleep: 5 * time.Second, honourCtx: true}
	fast := &fakeCollector{name: "fast", data: "x"}
	reg := NewRegistry([]Collector{polite, fast})
	reg.PerCollectorTimeout = 100 * time.Millisecond

	payload, err := reg.CollectAll(context.Background())
	if err != nil {
		t.Fatalf("CollectAll: %v", err)
	}
	if got := payload.Errors["polite"]; !strings.Contains(got, "deadline exceeded") {
		t.Fatalf("polite collector error = %q, want context deadline", got)
	}
	if payload.Data["fast"] != "x" {
		t.Fatalf("fast data missing")
	}
}

func TestCollectAll_AllFailed(t *testing.T) {
	reg := NewRegistry([]Collector{&fakeCollector{name: "a", err: errors.New("x")}})
	if _, err := reg.CollectAll(context.Background()); err == nil {
		t.Fatal("expected error when every collector fails")
	}
}

func TestNewRegistry_DefaultTimeout(t *testing.T) {
	if got := NewRegistry(nil).PerCollectorTimeout; got != DefaultCollectorTimeout {
		t.Fatalf("default timeout = %s", got)
	}
}

func TestRunCmd_DefaultDeadlineKillsWedgedCommand(t *testing.T) {
	// No deadline on the incoming context: runCmd must add its own and kill
	// the whole process group (sleep outlives sh).
	start := time.Now()
	_, err := runCmd(context.Background(), "sh", "-c", "sleep 30 & wait")
	if err == nil {
		t.Fatal("expected error from a killed command")
	}
	if elapsed := time.Since(start); elapsed > defaultCmdTimeout+5*time.Second {
		t.Fatalf("runCmd took %s; the default deadline did not apply", elapsed)
	}
}

func TestRunCmdTimeout_KillsProcessGroup(t *testing.T) {
	start := time.Now()
	_, err := runCmdTimeout(context.Background(), 300*time.Millisecond, "sh", "-c", "sleep 30 & wait")
	if err == nil {
		t.Fatal("expected error from a killed command")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("runCmdTimeout took %s; children were not killed with the group", elapsed)
	}
}

func TestRunCmdEnv_PassesEnvToChild(t *testing.T) {
	out, err := runCmdEnv(context.Background(), []string{"OPSERVO_TEST_VAR=hello"}, "sh", "-c", "printf %s \"$OPSERVO_TEST_VAR\"")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello" {
		t.Fatalf("env not passed: %q", out)
	}
}
