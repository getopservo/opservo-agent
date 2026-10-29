// Package executor runs commands dispatched from the Opservo cloud.
//
// SECURITY: this reverses the agent's historical read-only guarantee and is
// therefore OPT-IN and OFF BY DEFAULT. main.go only starts the executor when
// the operator passes --enable-actions / OPSERVO_ENABLE_ACTIONS=true on the
// server itself, so deploying a build that contains this package does not make
// any existing server remotely executable. Commands are pulled over the agent's
// existing outbound HTTPS connection (no inbound port) and the pending/result
// requests are HMAC-signed with the agent secret, exactly like heartbeats.
package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"syscall"
	"time"
)

// maxOutputBytes caps stdout/stderr captured per command so a runaway command
// cannot blow up memory or the result payload (agent_commands.stdout/stderr
// are stored forever as an audit log — this bounds that growth too). File
// downloads no longer go through this channel: the Files tab uses the
// disk-staged RELAY (the Opservo API's download-init/-relay/
// -fetch routes) for any file size, so this only needs to cover normal
// command output (ls, ps, log tails, etc.), not base64-encoded file bytes.
const maxOutputBytes = 64 * 1024

// capWriter is an io.Writer that records at most cap bytes and then counts the
// rest as truncated, without retaining it.
type capWriter struct {
	mu        sync.Mutex // Write runs on the process' pipe goroutine; String may be read mid-run for progress
	buf       bytes.Buffer
	cap       int
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if remaining := w.cap - w.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			w.buf.Write(p[:remaining])
			w.truncated = true
		} else {
			w.buf.Write(p)
		}
	} else if len(p) > 0 {
		w.truncated = true
	}
	// Always report the full length so the command's pipe never blocks.
	return len(p), nil
}

func (w *capWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.buf.String()
	if w.truncated {
		s += "\n…[output truncated]"
	}
	return s
}

// envDefaults are set for every command unless the agent's own environment
// already defines them. The agent normally runs under systemd, whose
// environment has no HOME/TERM/LANG, which broke git ("$HOME not set"),
// `clear`, a bare `cd` (landed in /) and anything that pages its output.
// Ordered so the resulting environment is deterministic.
//
// Known limitation: `sudo` resets the environment (env_reset), so these do not
// reach the command sudo runs — `sudo apt-get …` still needs
// `sudo DEBIAN_FRONTEND=noninteractive apt-get …` (or `sudo -E`) to stay
// non-interactive.
var envDefaults = [][2]string{
	{"TERM", "dumb"},
	{"PAGER", "cat"},
	{"SYSTEMD_PAGER", ""},
	{"PSQL_PAGER", "cat"},
	{"GIT_PAGER", "cat"},
	{"DEBIAN_FRONTEND", "noninteractive"},
	// Package installs never stop on a question (founder decision, 29 Oct
	// 2026): needrestart restarts services itself, ucf keeps the current
	// file, apt-listchanges stays quiet. dpkg's own conffile question is
	// answered through APT_CONFIG (aptconfig.go).
	{"NEEDRESTART_MODE", "a"},
	{"UCF_FORCE_CONFFOLD", "1"},
	{"APT_LISTCHANGES_FRONTEND", "none"},
	{"LANG", "C.UTF-8"},
}

// homeDir returns the agent user's home directory (root's when running as
// root), falling back to "/root" for uid 0 and "/" otherwise.
func homeDir() string {
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	if os.Geteuid() == 0 {
		return "/root"
	}
	return "/"
}

// commandEnv builds the environment for one command: the agent's inherited
// environment, plus HOME (when unset or empty) and envDefaults for any key the
// inherited environment does not set, plus the per-command env, which always
// wins. A command can still override any of these itself (`TERM=xterm cmd`,
// `export PAGER=less`).
func commandEnv(base []string, home string, extra map[string]string) []string {
	present := make(map[string]bool, len(base))
	homeSet := false
	for _, kv := range base {
		if i := strings.IndexByte(kv, '='); i > 0 {
			present[kv[:i]] = true
			if kv[:i] == "HOME" && kv[i+1:] != "" {
				homeSet = true
			}
		}
	}
	out := append([]string(nil), base...)
	if !homeSet && home != "" {
		out = append(out, "HOME="+home)
	}
	for _, d := range envDefaults {
		if !present[d[0]] {
			out = append(out, d[0]+"="+d[1])
		}
	}
	// os/exec dedups keeping the LAST value for a key, so the per-command env
	// overrides everything above.
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

// timeoutNote is appended to stderr whenever a command is killed for running
// past its timeout, so the reason is visible even when the command already
// wrote its own stderr (apt warnings used to hide it).
func timeoutNote(timeout time.Duration) string {
	if timeout%time.Second == 0 {
		return fmt.Sprintf("[opservo] command killed after %d s (timeout)", int(timeout/time.Second))
	}
	return fmt.Sprintf("[opservo] command killed after %.1f s (timeout)", timeout.Seconds())
}

// CommandResult is the outcome of running one dispatched command.
type CommandResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Status   string // "done" | "error" (error = could not launch / timed out)
}

// ProgressFunc receives the output captured so far. Called from a separate
// goroutine at most once per interval while the command runs: when something
// changed since the last call, and at least every progressKeepalive even when
// nothing did (a silent `sleep` or a quiet build must still be stoppable).
// Returning true stops the command: its whole process group is killed, the
// same way a timeout kills it. The caller only returns true after verifying a
// signed cancel from the API (see executor.go).
type ProgressFunc func(stdout, stderr string) (stop bool)

// progressKeepalive is how often progress is sent for a command whose output
// hasn't changed, so the API's "Stop now" reaches it. A var for tests.
var progressKeepalive = 5 * time.Second

// errStopped is the context cause when a command is stopped from the dashboard.
var errStopped = errors.New("stopped from the dashboard")

// stoppedNote is appended to stderr when a command is stopped from the
// dashboard, so its history shows why it ended.
const stoppedNote = "[opservo] command stopped from the dashboard"

// runCommand executes a shell command with a timeout, capturing capped
// stdout/stderr and the exit code. It never returns an error: launch/timeout
// failures are reported in the result (Status="error") so the caller always has
// something to send back to the cloud.
func runCommand(ctx context.Context, command string, env map[string]string, timeout time.Duration) CommandResult {
	return runCommandWithProgress(ctx, command, env, timeout, 0, nil)
}

// runCommandWithProgress is runCommand plus a periodic snapshot of the output
// while the command is still running (for the dashboard terminal to show a
// long command's output live). every <= 0 or a nil callback disables it.
func runCommandWithProgress(ctx context.Context, command string, env map[string]string, timeout, every time.Duration, onProgress ProgressFunc) CommandResult {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	sctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	cctx, cancel := context.WithTimeout(sctx, timeout)
	defer cancel()

	var stdout, stderr capWriter
	stdout.cap = maxOutputBytes
	stderr.cap = maxOutputBytes

	cmd := exec.CommandContext(cctx, "sh", "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Sane defaults (HOME, TERM, pagers off, …) plus per-command secrets (e.g.
	// a deploy's GitHub/Infisical credentials) as environment variables ONLY
	// for this process — secrets are never written to the command text, the
	// result, or disk.
	cmd.Env = withAptKeepConfig(commandEnv(os.Environ(), homeDir(), env), stateDir)
	// Run the command in its own process group and kill the WHOLE group on
	// timeout — otherwise a child that outlives `sh` (e.g. `sleep`) keeps the
	// stdout pipe open and cmd.Wait() blocks until it exits. WaitDelay is a
	// backstop so I/O copying can never hang Wait indefinitely.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second

	err := cmd.Start()
	if err == nil {
		if onProgress != nil && every > 0 {
			done := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				t := time.NewTicker(every)
				defer t.Stop()
				var lastOut, lastErr string
				lastSent := time.Now()
				for {
					select {
					case <-done:
						return
					case <-t.C:
						out, errOut := stdout.String(), stderr.String()
						if out != lastOut || errOut != lastErr || time.Since(lastSent) >= progressKeepalive {
							lastOut, lastErr = out, errOut
							lastSent = time.Now()
							if onProgress(out, errOut) {
								stop(errStopped)
								return
							}
						}
					}
				}
			}()
			err = cmd.Wait()
			close(done)
			wg.Wait()
		} else {
			err = cmd.Wait()
		}
	}
	res := CommandResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Status: "done",
	}

	if errors.Is(context.Cause(sctx), errStopped) {
		res.Status = "error"
		res.ExitCode = -1
		if res.Stderr == "" {
			res.Stderr = stoppedNote
		} else {
			res.Stderr += "\n" + stoppedNote
		}
		return res
	}
	if cctx.Err() == context.DeadlineExceeded {
		res.Status = "error"
		res.ExitCode = -1
		if res.Stderr == "" {
			res.Stderr = timeoutNote(timeout)
		} else {
			res.Stderr += "\n" + timeoutNote(timeout)
		}
		return res
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Command ran but exited non-zero — that's a normal "done" result.
			res.ExitCode = exitErr.ExitCode()
		} else {
			// Could not launch the command at all.
			res.Status = "error"
			res.ExitCode = -1
			if res.Stderr == "" {
				res.Stderr = err.Error()
			}
		}
	}
	return res
}
