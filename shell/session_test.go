package shell

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/user"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// A real session against a fake API: a real login shell on a real PTY,
// driven over a real WebSocket. Checks the three things that matter:
// output reaches the browser side, an echoed line is recorded, and a line
// typed with echo OFF (a password) is never recorded.
func TestSession_EndToEnd(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	if acct, _, err := lookupAccount(me.Username); err != nil || acct.Shell == "" {
		t.Skipf("current user %q is not a login user here", me.Username)
	}

	var mu sync.Mutex
	var output strings.Builder
	var lines []string
	var gotSig, gotAgent string
	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig, gotAgent = r.Header.Get("X-Signature"), r.Header.Get("X-Agent-ID")
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		go func() {
			send := func(s string) {
				_ = c.Write(ctx, websocket.MessageBinary, []byte(s))
				time.Sleep(300 * time.Millisecond)
			}
			time.Sleep(500 * time.Millisecond)
			send("echo hello-from-pty\r")
			send("read -s PW\r") // a password prompt: echo off, line mode on
			send("my-secret-password\r")
			send("echo len=${#PW}\r")
			// A full-screen program in front reads a key in raw mode (like
			// "q" quitting top); it must not prefix the next prompt line.
			// The key is sent only once that program prints READY, so it is
			// never typeahead for the shell (which really would join the line).
			send("stty raw -echo; bash -c 'echo RE\"\"ADY; head -c1 >/dev/null'; stty sane\r")
			for i := 0; i < 50; i++ {
				mu.Lock()
				ready := strings.Contains(output.String(), "READY")
				mu.Unlock()
				if ready {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			send("q")
			send("echo after-raw\r")
			send("exit\r")
		}()
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				close(done)
				return
			}
			mu.Lock()
			if typ == websocket.MessageBinary {
				output.Write(data)
			} else {
				var f struct{ Type, Text string }
				if json.Unmarshal(data, &f) == nil && f.Type == "line" {
					lines = append(lines, f.Text)
				}
			}
			mu.Unlock()
		}
	}))
	defer srv.Close()

	m := NewManager(srv.URL, "agent-1", "secret", testPub, false)
	errc := make(chan error, 1)
	go func() { errc <- m.run(context.Background(), Start{ID: "s1", OSUser: me.Username}) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("session did not finish")
	}
	if err := <-errc; err != nil {
		t.Fatalf("run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(output.String(), "hello-from-pty") {
		t.Errorf("shell output did not come back: %q", output.String())
	}
	if !strings.Contains(output.String(), "len=18") {
		t.Errorf("the secret did not reach the shell: %q", output.String())
	}
	if gotAgent != "agent-1" || len(gotSig) != 64 {
		t.Errorf("dial was not HMAC-authenticated: agent=%q sig=%q", gotAgent, gotSig)
	}
	joined := strings.Join(lines, "|")
	if !strings.Contains(joined, "echo hello-from-pty") || !strings.Contains(joined, "read -s PW") {
		t.Errorf("lines typed at the shell prompt not recorded: %q", lines)
	}
	if !strings.Contains(joined, "echo after-raw") || strings.Contains(joined, "qecho after-raw") {
		t.Errorf("a key read by a full-screen program leaked into the next line: %q", lines)
	}
	if strings.Contains(joined, "my-secret-password") {
		t.Fatalf("a line typed with echo OFF was recorded: %q", lines)
	}
	if strings.Contains(output.String(), "my-secret-password") {
		t.Errorf("echo-off input appeared in the output: %q", output.String())
	}
}

func TestSecretSafe(t *testing.T) {
	const echo, icanon = 0x8, 0x2 // unix.ECHO, unix.ICANON on Linux
	cases := []struct {
		name  string
		lflag uint32
		want  bool
	}{
		{"cooked with echo (cat, plain read)", echo | icanon, true},
		{"readline / vim / top (raw, app echoes)", 0, true},
		{"password prompt (line mode, no echo)", icanon, false},
	}
	for _, c := range cases {
		if got := secretSafe(c.lflag); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
