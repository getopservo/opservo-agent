package shell

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

const (
	// MaxSessions open at once on one server (the API enforces the same).
	MaxSessions = 3
	// MaxDuration is the agent-side backstop; the API closes idle sessions
	// sooner (15 min without traffic).
	MaxDuration = 4 * time.Hour
	readChunk   = 32 * 1024
)

// Manager opens sessions the API hands over. One per agent process.
type Manager struct {
	apiURL   string
	agentID  string
	secret   string
	pubKey   string
	insecure bool // --dev: skip TLS verification, like the sender

	mu     sync.Mutex
	active map[string]bool
}

func NewManager(apiURL, agentID, secret, pubKeyHex string, insecure bool) *Manager {
	return &Manager{apiURL: apiURL, agentID: agentID, secret: secret, pubKey: pubKeyHex, insecure: insecure, active: map[string]bool{}}
}

// Open verifies a start and, when it checks out, runs the session in the
// background. Refusals are logged loudly; nothing is opened.
func (m *Manager) Open(ctx context.Context, s Start) {
	if err := VerifyStart(m.pubKey, m.agentID, s, time.Now()); err != nil {
		slog.Error("REFUSING live terminal session — not opening a shell", "session_id", s.ID, "error", err)
		return
	}
	m.mu.Lock()
	if m.active[s.ID] || len(m.active) >= MaxSessions {
		m.mu.Unlock()
		slog.Warn("live terminal session not opened: already open or too many sessions", "session_id", s.ID)
		return
	}
	m.active[s.ID] = true
	m.mu.Unlock()
	go func() {
		defer func() { m.mu.Lock(); delete(m.active, s.ID); m.mu.Unlock() }()
		slog.Warn("LIVE TERMINAL session opening", "session_id", s.ID, "user", s.OSUser)
		err := m.run(ctx, s)
		slog.Warn("live terminal session ended", "session_id", s.ID, "error", err)
	}()
}

func wsURL(apiURL string) string {
	switch {
	case strings.HasPrefix(apiURL, "https://"):
		return "wss://" + strings.TrimPrefix(apiURL, "https://")
	case strings.HasPrefix(apiURL, "http://"):
		return "ws://" + strings.TrimPrefix(apiURL, "http://")
	}
	return apiURL
}

// dialSignature authenticates the agent's WebSocket: HMAC over
// "<session id>\n<timestamp>" with the agent secret, like a heartbeat.
func dialSignature(secret, sessionID, ts string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sessionID + "\n" + ts))
	return hex.EncodeToString(mac.Sum(nil))
}

type control struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

func sendJSON(ctx context.Context, c *websocket.Conn, v interface{}) {
	b, _ := json.Marshal(v)
	_ = c.Write(ctx, websocket.MessageText, b)
}

// sessionEnv is the shell's whole environment. Built from scratch — never the
// agent's own environment, which holds its secret key.
func sessionEnv(a Account) []string {
	return []string{
		"HOME=" + a.Home,
		"USER=" + a.Name,
		"LOGNAME=" + a.Name,
		"SHELL=" + a.Shell,
		"TERM=xterm-256color",
		"LANG=C.UTF-8",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
}

// recordable reports whether input typed now may go into the recording.
//
// A password prompt (sudo, `read -s`, mysql/psql, ssh, getpass) turns ECHO
// off but keeps the terminal in line mode (ICANON on): that input is never
// recorded. Shell prompts are different: bash's readline (and vim, top, less)
// turn ECHO *and* ICANON off and echo keystrokes themselves, so "ECHO off"
// alone can't mean "secret". Known gap: a full-screen program that reads a
// secret in raw mode (e.g. vim's :X key prompt) is recorded.
func recordable(tty *os.File) bool {
	t, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if err != nil {
		return false // unknown → record nothing
	}
	return secretSafe(t.Lflag)
}

// foreground returns the terminal's foreground process group (the shell, or
// the program it is running — top, vim, mysql). -1 when unknown. Asked on the
// MASTER side: on the slave, Linux answers only to processes in that session.
func foreground(ptmx *os.File) int {
	pg, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPGRP)
	if err != nil {
		return -1
	}
	return pg
}

// secretSafe is the pure part of recordable, for tests.
func secretSafe(lflag uint32) bool {
	echo := lflag&unix.ECHO != 0
	canonical := lflag&unix.ICANON != 0
	return echo || !canonical
}

func (m *Manager) run(parent context.Context, s Start) error {
	ctx, cancel := context.WithTimeout(parent, MaxDuration)
	defer cancel()

	ts := time.Now().UTC().Format(time.RFC3339)
	h := http.Header{}
	h.Set("X-Agent-ID", m.agentID)
	h.Set("X-Timestamp", ts)
	h.Set("X-Signature", dialSignature(m.secret, s.ID, ts))
	opts := &websocket.DialOptions{HTTPHeader: h}
	if m.insecure {
		opts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // --dev only
	}
	dctx, dcancel := context.WithTimeout(ctx, 20*time.Second)
	conn, _, err := websocket.Dial(dctx, wsURL(m.apiURL)+"/api/v1/agents/"+m.agentID+"/shell/"+s.ID+"/connect", opts)
	dcancel()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)

	fail := func(msg string) error {
		sendJSON(ctx, conn, map[string]string{"type": "error", "message": msg})
		_ = conn.Close(websocket.StatusNormalClosure, "")
		return errors.New(msg)
	}

	acct, groups, err := lookupAccount(s.OSUser)
	if err != nil {
		return fail(err.Error())
	}
	cmd := exec.Command(acct.Shell, "-l")
	cmd.Dir = acct.Home
	cmd.Env = sessionEnv(acct)
	attr := &syscall.SysProcAttr{Setsid: true, Setctty: true}
	switch euid := os.Geteuid(); {
	case euid == 0:
		attr.Credential = &syscall.Credential{Uid: acct.UID, Gid: acct.GID, Groups: groups}
	case uint32(euid) != acct.UID:
		return fail(fmt.Sprintf("the agent isn't running as root, so a session can only run as its own user, not %q", acct.Name))
	}
	cmd.SysProcAttr = attr

	ptmx, tty, err := pty.Open()
	if err != nil {
		return fail("could not allocate a terminal: " + err.Error())
	}
	defer ptmx.Close()
	defer tty.Close() // kept open in the agent to read the ECHO flag
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	if err := cmd.Start(); err != nil {
		return fail("could not start " + acct.Shell + ": " + err.Error())
	}
	_ = pty.Setsize(ptmx, &pty.Winsize{Cols: 120, Rows: 32})

	exited := make(chan int, 1)
	go func() {
		code := 0
		if err := cmd.Wait(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else {
				code = -1
			}
		}
		exited <- code
	}()

	// Shell output → browser (via the API, which records it).
	go func() {
		buf := make([]byte, readChunk)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				if werr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Browser → shell. Echoed lines also go back as "line" frames for the
	// recording; input typed with echo off goes to the shell only.
	go func() {
		defer cancel()
		var rec lineRecorder
		wasEcho := true
		lastFg := foreground(ptmx)
		for {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			if typ == websocket.MessageText {
				var c control
				if json.Unmarshal(data, &c) != nil {
					continue
				}
				switch c.Type {
				case "resize":
					if c.Cols > 0 && c.Rows > 0 && c.Cols < 1000 && c.Rows < 500 {
						_ = pty.Setsize(ptmx, &pty.Winsize{Cols: c.Cols, Rows: c.Rows})
					}
				case "close":
					return
				}
				continue
			}
			// A different program in front (shell → top → shell) starts a new
			// line: keys pressed inside top or vim (the "q" that quits top)
			// must not be glued onto the next command typed at the prompt.
			if fg := foreground(ptmx); fg != lastFg {
				rec.Reset()
				lastFg = fg
			}
			echo := recordable(tty)
			if echo {
				if !wasEcho {
					rec.Reset()
				}
				for _, line := range rec.Feed(data) {
					sendJSON(ctx, conn, map[string]string{"type": "line", "text": line})
				}
			} else {
				rec.Reset()
			}
			wasEcho = echo
			if _, err := ptmx.Write(data); err != nil {
				return
			}
		}
	}()

	select {
	case code := <-exited:
		sendJSON(ctx, conn, map[string]interface{}{"type": "exit", "code": code})
		_ = conn.Close(websocket.StatusNormalClosure, "shell exited")
		return nil
	case <-ctx.Done():
		// Browser left, API closed it, a lock was turned off, or 4 h passed:
		// hang up the whole session (shell + anything it started).
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGHUP)
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-exited
		}
		_ = conn.Close(websocket.StatusNormalClosure, "session closed")
		return ctx.Err()
	}
}
