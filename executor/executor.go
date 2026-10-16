package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/getopservo/opservo-agent/collectors"
	"github.com/getopservo/opservo-agent/reqsign"
	"github.com/getopservo/opservo-agent/shell"
)

// commandSigningPublicKeyHex is the Ed25519 public key (64 hex chars) used to
// verify a dispatched command's signature before running it. It is set to the
// Opservo API's command-signing key (an empty value would disable
// verification). The agent REFUSES to run any command whose
// signature doesn't verify against id+agent_id+command+expires_at — so DB
// write access to agent_commands alone is no longer sufficient to queue
// execution; the attacker would also need the signing key, which lives only
// in the running API's memory, never in the codebase or an image layer.
// Mirrors the update-manifest signing convention in updater/updater.go (signingPublicKeyHex) — same rollout shape, a
// DIFFERENT dedicated keypair (this one must be usable by a live process, so
// it can't be the build-only update-signing key).
//
// A var so another environment's build can link in its own key
// (-ldflags "-X github.com/getopservo/opservo-agent/executor.commandSigningPublicKeyHex=…",
// set from api/Dockerfile's COMMAND_SIGNING_PUBKEY build arg). Keep
// prober.probeSigningPublicKeyHex in step — the API signs both with one keypair.
var commandSigningPublicKeyHex = "e1a4093b146bf6f33492aba76692362111b6abadeb8d46f90cd891fa9c4e1c7a"

// Executor polls the Opservo API for pending commands and runs them. It is
// started unless the operator hard-disables it locally
// (OPSERVO_ENABLE_ACTIONS=false); the API only hands it commands for servers
// whose remote actions are switched on in the dashboard.
type Executor struct {
	apiURL    string
	agentID   string
	secretKey string
	interval  time.Duration
	client    *http.Client
	// shell opens live terminal sessions delivered in the poll response; nil
	// when OPSERVO_ENABLE_SHELL is off, and then any delivered start is ignored.
	shell *shell.Manager
	// Commands run one at a time, in order, on a worker goroutine fed by
	// queue, so the poll loop keeps running while a long command (a 600 s apt
	// upgrade) is in flight: live-terminal starts are opened at once instead
	// of waiting behind it. inFlight counts queued + running commands; while
	// it is > 0 the poll says `busy`, and the API leaves new commands pending
	// (still stoppable from the dashboard) instead of handing them over to
	// wait here. Old APIs ignore `busy` and the commands just queue locally.
	queue    chan pendingCommand
	inFlight atomic.Int32
}

// maxQueued bounds the local queue (an old API ignoring `busy` could hand
// over more); a command that doesn't fit is refused, never silently dropped.
const maxQueued = 64

// WithShell turns on live terminal sessions for this executor.
func (e *Executor) WithShell(m *shell.Manager) *Executor { e.shell = m; return e }

// CommandSigningPublicKeyHex is the embedded command-signing public key, which
// also verifies live terminal session starts.
func CommandSigningPublicKeyHex() string { return commandSigningPublicKeyHex }

func New(apiURL, agentID, secretKey string, interval time.Duration) *Executor {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &Executor{
		apiURL:    apiURL,
		agentID:   agentID,
		secretKey: secretKey,
		interval:  interval,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

type pendingCommand struct {
	ID             string            `json:"id"`
	Command        string            `json:"command"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	Signature      string            `json:"signature"`     // hex Ed25519 sig, "" if signing is off API-side
	ExpiresAt      string            `json:"expires_at"`    // exact string the API signed — verified as opaque text, never reformatted
	Env            map[string]string `json:"env,omitempty"` // per-command secrets injected as env vars — deliberately EXCLUDED from the signature (resolved fresh per poll by the API)
}

// verifyCommandSignature reconstructs the exact message the API signed
// (id+agent_id+command+expires_at, newline-joined — must match
// the Opservo API's commandSigningMessage byte-for-byte) and
// checks it against pubKeyHex. Fails CLOSED on any malformed input. A no-op
// (always passes) when pubKeyHex is empty, so this can ship before the key is
// provisioned without breaking anything. Pure/parameterized (mirrors
// updater.verifyManifestSignature) so it's testable without the package const.
func verifyCommandSignature(pubKeyHex, agentID string, c pendingCommand) error {
	if pubKeyHex == "" {
		return nil
	}
	pub, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad embedded command-signing public key")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(c.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("missing or malformed signature")
	}
	msg := c.ID + "\n" + agentID + "\n" + c.Command + "\n" + c.ExpiresAt
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(msg), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// checkCommandExpiry refuses a command whose signed expires_at has passed.
// The signature proves the API issued it, not that it is still wanted: a
// captured poll response replayed later would otherwise run stale commands.
// The API always sets expires_at (RFC 3339), so an empty or unparseable value
// is treated as expired, not as "no deadline".
func checkCommandExpiry(c pendingCommand, now time.Time) error {
	exp, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil {
		return fmt.Errorf("command expired: bad expiry %q", c.ExpiresAt)
	}
	if !now.Before(exp) {
		return fmt.Errorf("command expired at %s", c.ExpiresAt)
	}
	return nil
}

// verifyCancelSignature checks a "stop this command" instruction from the API.
// The message is domain-tagged ("cancel" first line, which a command message —
// it starts with a UUID — or a probe message never is) and names one command
// on one agent, so a captured cancel can only ever stop that same command.
// Must match the API's cancelSigningMessage byte-for-byte. Same fail-closed
// and empty-key conventions as verifyCommandSignature.
func verifyCancelSignature(pubKeyHex, agentID, commandID, sigHex string) error {
	if pubKeyHex == "" {
		return nil
	}
	pub, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad embedded command-signing public key")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("missing or malformed signature")
	}
	msg := "cancel\n" + commandID + "\n" + agentID
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(msg), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// progressEvery is how often a running command's partial output is pushed to
// the API so the dashboard terminal can show it live.
const progressEvery = time.Second

// minPollInterval bounds how fast the API may ask us to poll (see nextInterval).
const minPollInterval = 500 * time.Millisecond

// Run polls for and executes pending commands until ctx is cancelled. It logs
// loudly: remote execution should never be silent.
//
// The cadence is normally e.interval, but each poll response may carry a
// `poll_interval_ms` hint: while someone has a dashboard terminal open to this
// server the API asks for ~1 s so a typed command is picked up almost at once.
// The hint only ever applies until the next response, so a lost connection or
// an old API silently falls back to the default cadence.
func (e *Executor) Run(ctx context.Context) {
	slog.Warn("REMOTE ACTIONS ENABLED — this server will execute commands dispatched from Opservo",
		"agent_id", e.agentID, "poll_interval", e.interval)
	e.queue = make(chan pendingCommand, maxQueued)
	go e.worker(ctx)
	timer := time.NewTimer(e.interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			hint := e.poll(ctx)
			timer.Reset(nextInterval(e.interval, hint))
		}
	}
}

// nextInterval clamps an API-supplied poll hint to [minPollInterval, base];
// a zero/negative hint means "use the base cadence". The API can only ever
// make us poll FASTER than configured, never slower.
func nextInterval(base, hint time.Duration) time.Duration {
	if hint <= 0 || hint >= base {
		return base
	}
	if hint < minPollInterval {
		return minPollInterval
	}
	return hint
}

func (e *Executor) poll(ctx context.Context) (hint time.Duration) {
	cmds, shells, hint, err := e.fetchPending(ctx, e.inFlight.Load() > 0)
	if err != nil {
		slog.Debug("command poll failed", "error", err)
		return 0
	}
	for _, s := range shells {
		if e.shell == nil {
			slog.Warn("live terminal session requested but OPSERVO_ENABLE_SHELL is off on this server — ignored", "session_id", s.ID)
			continue
		}
		e.shell.Open(ctx, s)
	}
	for _, c := range cmds {
		e.enqueue(ctx, c)
	}
	return hint
}

// enqueue hands a command to the worker, or refuses it (with a result the
// dashboard shows) when the local queue is full.
func (e *Executor) enqueue(ctx context.Context, c pendingCommand) {
	e.inFlight.Add(1)
	select {
	case e.queue <- c:
	default:
		e.inFlight.Add(-1)
		slog.Error("command queue full — refusing command", "command_id", c.ID)
		res := CommandResult{Status: "error", ExitCode: -1, Stderr: "rejected: this server is still running earlier commands; try again when they finish"}
		if serr := e.submitResult(ctx, c.ID, res); serr != nil {
			slog.Warn("failed to submit command result", "command_id", c.ID, "error", serr)
		}
	}
}

// worker runs queued commands one after another, in the order received.
func (e *Executor) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-e.queue:
			e.execute(ctx, c)
			e.inFlight.Add(-1)
		}
	}
}

// execute verifies one command (signature, expiry, self-protection), runs it
// with live progress + remote stop, and reports the result.
func (e *Executor) execute(ctx context.Context, c pendingCommand) {
	if err := verifyCommandSignature(commandSigningPublicKeyHex, e.agentID, c); err != nil {
		slog.Error("REFUSING unsigned/invalid command — not executing", "command_id", c.ID, "error", err)
		res := CommandResult{Status: "error", ExitCode: -1, Stderr: "rejected: " + err.Error()}
		if serr := e.submitResult(ctx, c.ID, res); serr != nil {
			slog.Warn("failed to submit command result", "command_id", c.ID, "error", serr)
		}
		return
	}
	if err := checkCommandExpiry(c, time.Now()); err != nil {
		slog.Error("REFUSING expired command — not executing", "command_id", c.ID, "error", err)
		res := CommandResult{Status: "error", ExitCode: -1, Stderr: "rejected: " + err.Error()}
		if serr := e.submitResult(ctx, c.ID, res); serr != nil {
			slog.Warn("failed to submit command result", "command_id", c.ID, "error", serr)
		}
		return
	}
	if touchesAgentSwitches(c.Command) {
		slog.Error("REFUSING command that touches the agent's own switches — not executing", "command_id", c.ID)
		res := CommandResult{Status: "error", ExitCode: -1, Stderr: selfProtectMessage}
		if serr := e.submitResult(ctx, c.ID, res); serr != nil {
			slog.Warn("failed to submit command result", "command_id", c.ID, "error", serr)
		}
		return
	}
	slog.Warn("executing dispatched command", "command_id", c.ID, "command", logCommand(c.Command), "has_secrets", len(c.Env) > 0)
	id := c.ID
	res := runCommandWithProgress(ctx, c.Command, c.Env, time.Duration(c.TimeoutSeconds)*time.Second, progressEvery, func(stdout, stderr string) bool {
		cancelSig, perr := e.submitProgress(ctx, id, stdout, stderr)
		if perr != nil {
			slog.Debug("failed to submit command progress", "command_id", id, "error", perr)
			return false
		}
		if cancelSig == nil {
			return false
		}
		if err := verifyCancelSignature(commandSigningPublicKeyHex, e.agentID, id, *cancelSig); err != nil {
			slog.Error("IGNORING stop request with a bad signature — command keeps running", "command_id", id, "error", err)
			return false
		}
		slog.Warn("stopping command: stop requested from the dashboard", "command_id", id)
		return true
	})
	slog.Warn("command finished", "command_id", c.ID, "status", res.Status, "exit_code", res.ExitCode)
	if err := e.submitResult(ctx, c.ID, res); err != nil {
		slog.Warn("failed to submit command result", "command_id", c.ID, "error", err)
	}
}

// fetchPending asks the API for queued commands. The request body is HMAC-signed
// with the agent secret (same scheme as heartbeats) so the API can authenticate
// the agent, and marks the returned commands as dispatched server-side.
// It also returns the API's poll-cadence hint (0 when absent).
func (e *Executor) fetchPending(ctx context.Context, busy bool) ([]pendingCommand, []shell.Start, time.Duration, error) {
	req := map[string]interface{}{"timestamp": time.Now().UTC().Format(time.RFC3339)}
	if busy {
		req["busy"] = true
	}
	body, _ := json.Marshal(req)
	resp, err := e.signedPost(ctx, "/api/v1/agents/"+e.agentID+"/commands/poll", body)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, 0, fmt.Errorf("poll status %d", resp.StatusCode)
	}
	var out struct {
		Commands       []pendingCommand `json:"commands"`
		ShellSessions  []shell.Start    `json:"shell_sessions"`
		PollIntervalMs int              `json:"poll_interval_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, nil, 0, err
	}
	return out.Commands, out.ShellSessions, time.Duration(out.PollIntervalMs) * time.Millisecond, nil
}

// submitProgress pushes the output captured so far for a still-running
// command. Best-effort: an old API (404) or a blip just means the dashboard
// sees the output when the command finishes, as before. When someone pressed
// "Stop now", the response carries a cancel signature (returned unverified —
// the caller verifies it); nil means keep running.
func (e *Executor) submitProgress(ctx context.Context, commandID, stdout, stderr string) (*string, error) {
	body, _ := json.Marshal(map[string]string{"stdout": stdout, "stderr": stderr})
	resp, err := e.signedPost(ctx, "/api/v1/agents/"+e.agentID+"/commands/"+commandID+"/progress", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("progress status %d", resp.StatusCode)
	}
	var out struct {
		Cancel *struct {
			Signature string `json:"signature"`
		} `json:"cancel"`
	}
	// An old API answers {received:true}; a body we can't parse is "no cancel".
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Cancel == nil {
		return nil, nil
	}
	return &out.Cancel.Signature, nil
}

func (e *Executor) submitResult(ctx context.Context, commandID string, res CommandResult) error {
	body, _ := json.Marshal(map[string]interface{}{
		"exit_code": res.ExitCode,
		"stdout":    res.Stdout,
		"stderr":    res.Stderr,
		"status":    res.Status,
	})
	resp, err := e.signedPost(ctx, "/api/v1/agents/"+e.agentID+"/commands/"+commandID+"/result", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("result status %d", resp.StatusCode)
	}
	return nil
}

func (e *Executor) signedPost(ctx context.Context, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.apiURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", e.agentID)
	// v2 HMAC: timestamp + nonce bound into the signature (reqsign).
	reqsign.Apply(req.Header, e.secretKey, body)
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// A 401 for clock skew is fixable with NTP; say so (throttled) and
		// hand the response back untouched for the caller's normal handling.
		// The body is small; re-wrap it so the caller can still read it.
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		reqsign.WarnClockSkew(resp.StatusCode, errBody, path)
		resp.Body = io.NopCloser(bytes.NewReader(errBody))
	}
	return resp, nil
}

// logCommandMax is how much of a dispatched command's text reaches the journal.
const logCommandMax = 120

// logCommand is the form of a command that is safe to log: secrets masked
// (RedactSecrets, the same masker the log shipper uses) and truncated to
// logCommandMax runes, so a long heredoc or an inline credential never lands
// in journald, which every local admin can read. The full text is in
// agent_commands on the API, where it is audited and access-controlled.
func logCommand(cmd string) string {
	cmd = collectors.RedactSecrets(cmd)
	if r := []rune(cmd); len(r) > logCommandMax {
		return string(r[:logCommandMax]) + "…"
	}
	return cmd
}
