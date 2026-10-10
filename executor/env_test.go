package executor

import (
	"context"
	"strings"
	"testing"
	"time"
)

func envValue(env []string, key string) (string, bool) {
	// os/exec keeps the LAST value for a duplicated key; mirror that.
	val, ok := "", false
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			val, ok = kv[len(key)+1:], true
		}
	}
	return val, ok
}

func TestCommandEnv_AddsDefaultsWhenUnset(t *testing.T) {
	env := commandEnv([]string{"PATH=/usr/bin"}, "/root", nil)
	want := map[string]string{
		"HOME": "/root", "TERM": "dumb", "PAGER": "cat", "SYSTEMD_PAGER": "",
		"PSQL_PAGER": "cat", "GIT_PAGER": "cat", "DEBIAN_FRONTEND": "noninteractive",
		"LANG": "C.UTF-8", "PATH": "/usr/bin",
	}
	for k, v := range want {
		got, ok := envValue(env, k)
		if !ok || got != v {
			t.Errorf("%s = %q (set=%v), want %q", k, got, ok, v)
		}
	}
}

func TestCommandEnv_KeepsInheritedValues(t *testing.T) {
	env := commandEnv([]string{"HOME=/home/opservo", "LANG=en_IN.UTF-8", "TERM=xterm"}, "/root", nil)
	for k, v := range map[string]string{"HOME": "/home/opservo", "LANG": "en_IN.UTF-8", "TERM": "xterm"} {
		if got, _ := envValue(env, k); got != v {
			t.Errorf("%s = %q, want inherited %q", k, got, v)
		}
	}
}

func TestCommandEnv_EmptyHomeIsReplaced(t *testing.T) {
	env := commandEnv([]string{"HOME="}, "/root", nil)
	if got, _ := envValue(env, "HOME"); got != "/root" {
		t.Errorf("HOME = %q, want /root", got)
	}
}

func TestCommandEnv_PerCommandEnvWins(t *testing.T) {
	env := commandEnv(nil, "/root", map[string]string{"TERM": "xterm-256color", "TOKEN": "s3cret"})
	if got, _ := envValue(env, "TERM"); got != "xterm-256color" {
		t.Errorf("TERM = %q, want per-command value", got)
	}
	if got, _ := envValue(env, "TOKEN"); got != "s3cret" {
		t.Errorf("TOKEN = %q", got)
	}
}

func TestRunCommand_EnvDefaultsReachTheCommand(t *testing.T) {
	res := runCommand(context.Background(), `printf '%s|%s' "$DEBIAN_FRONTEND" "${HOME:+set}"`, nil, 5*time.Second)
	if res.Status != "done" || res.ExitCode != 0 {
		t.Fatalf("unexpected result %+v", res)
	}
	// DEBIAN_FRONTEND is never set by a test runner; HOME must always be set.
	if res.Stdout != "noninteractive|set" {
		t.Errorf("env not applied: %q", res.Stdout)
	}
	// A command can still override a default itself.
	res = runCommand(context.Background(), `PAGER=less sh -c 'printf %s "$PAGER"'`, nil, 5*time.Second)
	if res.Stdout != "less" {
		t.Errorf("inline override lost: %q", res.Stdout)
	}
}

func TestRunCommand_TimeoutAlwaysExplained(t *testing.T) {
	// A command that writes its own stderr before being killed: the timeout
	// note must still be appended (it used to be hidden behind apt warnings).
	res := runCommand(context.Background(), "echo 'W: some apt warning' >&2; sleep 5", nil, 300*time.Millisecond)
	if res.Status != "error" || res.ExitCode != -1 {
		t.Fatalf("expected error/-1, got %+v", res)
	}
	if !strings.Contains(res.Stderr, "some apt warning") {
		t.Errorf("own stderr lost: %q", res.Stderr)
	}
	if !strings.HasSuffix(res.Stderr, "\n[opservo] command killed after 0.3 s (timeout)") {
		t.Errorf("timeout note missing: %q", res.Stderr)
	}
	// Silent command: the note is the whole stderr.
	res = runCommand(context.Background(), "sleep 5", nil, 200*time.Millisecond)
	if res.Stderr != "[opservo] command killed after 0.2 s (timeout)" {
		t.Errorf("stderr = %q", res.Stderr)
	}
}

func TestTimeoutNote_WholeSeconds(t *testing.T) {
	if got := timeoutNote(600 * time.Second); got != "[opservo] command killed after 600 s (timeout)" {
		t.Errorf("got %q", got)
	}
}
