package shell

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Same test keypair as the command-signing interop tests; the API's
// lib/commandSigning.test.ts "shellSigning" pins this exact signature.
const (
	testPub   = "1d53ae157ea41fc42412ffa3d865cce96cd1b57441bdde097c91f00dea5b217e"
	testSig   = "e8f3815ef6db594aad44528f3b0fc60013b60a4031024ed85b3a2e0c8ddc22108e5a65b6caae60a2af94ddea9583dc8ffcfb0b986b75afd0dd20c40058b8cc05"
	testSID   = "22222222-3333-4444-5555-666666666666"
	testAgent = "agent-1"
)

var testStart = Start{ID: testSID, OSUser: "ubuntu", ExpiresAt: "2026-10-11T12:01:00.000Z", Signature: testSig}
var beforeExpiry = time.Date(2026, 10, 11, 12, 0, 30, 0, time.UTC)

func TestVerifyStart_InteropWithTypeScriptSigner(t *testing.T) {
	if err := VerifyStart(testPub, testAgent, testStart, beforeExpiry); err != nil {
		t.Fatalf("TypeScript-produced start did not verify: %v", err)
	}
}

func TestVerifyStart_Refusals(t *testing.T) {
	cases := map[string]struct {
		pub   string
		agent string
		s     Start
		now   time.Time
		want  string
	}{
		"expired":                 {testPub, testAgent, testStart, time.Date(2026, 10, 11, 12, 1, 0, 0, time.UTC), "expired"},
		"other agent":             {testPub, "agent-2", testStart, beforeExpiry, "verification failed"},
		"user swapped to root":    {testPub, testAgent, Start{ID: testSID, OSUser: "root", ExpiresAt: testStart.ExpiresAt, Signature: testSig}, beforeExpiry, "verification failed"},
		"expiry extended":         {testPub, testAgent, Start{ID: testSID, OSUser: "ubuntu", ExpiresAt: "2026-10-11T13:01:00.000Z", Signature: testSig}, beforeExpiry, "verification failed"},
		"unsigned":                {testPub, testAgent, Start{ID: testSID, OSUser: "ubuntu", ExpiresAt: testStart.ExpiresAt}, beforeExpiry, "malformed signature"},
		"no key = never open one": {"", testAgent, testStart, beforeExpiry, "no valid signing key"},
	}
	for name, c := range cases {
		err := VerifyStart(c.pub, c.agent, c.s, c.now)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", name, err, c.want)
		}
	}
}

func TestStartMessage_DomainTag(t *testing.T) {
	if got := startMessage(testAgent, testStart); got != "shell\n"+testSID+"\nagent-1\nubuntu\n2026-10-11T12:01:00.000Z" {
		t.Fatalf("start message changed: %q", got)
	}
}

func TestLineRecorder(t *testing.T) {
	var r lineRecorder
	got := r.Feed([]byte("ls -la\r"))
	got = append(got, r.Feed([]byte("cd /etx\x7fc\r"))...)               // backspace edits
	got = append(got, r.Feed([]byte("rm -rf /\x03"))...)                 // Ctrl-C: abandoned, not recorded
	got = append(got, r.Feed([]byte("vim \x1b[A\x1b[Bnginx.conf\r"))...) // arrow keys dropped
	got = append(got, r.Feed([]byte("junk\x15top\r"))...)                // Ctrl-U kills the line
	got = append(got, r.Feed([]byte("\r\r"))...)                         // empty Enter: nothing
	want := []string{"ls -la", "cd /etc", "vim nginx.conf", "top"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestLineRecorder_SplitAcrossChunks(t *testing.T) {
	var r lineRecorder
	if out := r.Feed([]byte("syst")); len(out) != 0 {
		t.Fatalf("partial line emitted: %q", out)
	}
	if out := r.Feed([]byte("emctl status nginx\r")); !reflect.DeepEqual(out, []string{"systemctl status nginx"}) {
		t.Fatalf("got %q", out)
	}
	// Reset (echo turned off) drops a half-typed line.
	r.Feed([]byte("sudo -k"))
	r.Reset()
	if out := r.Feed([]byte("\r")); len(out) != 0 {
		t.Fatalf("line survived Reset: %q", out)
	}
}

func TestLoginAccounts(t *testing.T) {
	passwd := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"postgres:x:114:120::/var/lib/postgresql:/bin/bash", // system uid → not offered
		"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash",
		"deploy:x:1001:1001::/home/deploy:/bin/zsh",
		"locked:x:1002:1002::/home/locked:/bin/false",
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
		"# comment",
		"broken:line",
	}, "\n")
	var names []string
	for _, a := range loginAccounts(parsePasswd(strings.NewReader(passwd))) {
		names = append(names, a.Name)
	}
	if want := []string{"root", "ubuntu", "deploy"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("got %v, want %v", names, want)
	}
}

func TestSessionEnvNeverInheritsAgentSecrets(t *testing.T) {
	t.Setenv("OPSERVO_SECRET_KEY", "super-secret")
	env := strings.Join(sessionEnv(Account{Name: "ubuntu", Home: "/home/ubuntu", Shell: "/bin/bash"}), "\n")
	if strings.Contains(env, "super-secret") || strings.Contains(env, "OPSERVO_") {
		t.Fatalf("agent environment leaked into the shell: %q", env)
	}
	if !strings.Contains(env, "HOME=/home/ubuntu") || !strings.Contains(env, "TERM=xterm-256color") {
		t.Fatalf("missing basics: %q", env)
	}
}

func TestWsURL(t *testing.T) {
	if wsURL("https://api.getopservo.com") != "wss://api.getopservo.com" || wsURL("http://localhost:3001") != "ws://localhost:3001" {
		t.Fatal("ws url mapping")
	}
}
