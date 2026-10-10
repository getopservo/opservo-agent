package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
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
const commandSigningPublicKeyHex = "e1a4093b146bf6f33492aba76692362111b6abadeb8d46f90cd891fa9c4e1c7a"

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
}

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
	cmds, hint, err := e.fetchPending(ctx)
	if err != nil {
		slog.Debug("command poll failed", "error", err)
		return 0
	}
	for _, c := range cmds {
		if err := verifyCommandSignature(commandSigningPublicKeyHex, e.agentID, c); err != nil {
			slog.Error("REFUSING unsigned/invalid command — not executing", "command_id", c.ID, "error", err)
			res := CommandResult{Status: "error", ExitCode: -1, Stderr: "rejected: " + err.Error()}
			if serr := e.submitResult(ctx, c.ID, res); serr != nil {
				slog.Warn("failed to submit command result", "command_id", c.ID, "error", serr)
			}
			continue
		}
		slog.Warn("executing dispatched command", "command_id", c.ID, "command", c.Command, "has_secrets", len(c.Env) > 0)
		id := c.ID
		res := runCommandWithProgress(ctx, c.Command, c.Env, time.Duration(c.TimeoutSeconds)*time.Second, progressEvery, func(stdout, stderr string) {
			if perr := e.submitProgress(ctx, id, stdout, stderr); perr != nil {
				slog.Debug("failed to submit command progress", "command_id", id, "error", perr)
			}
		})
		slog.Warn("command finished", "command_id", c.ID, "status", res.Status, "exit_code", res.ExitCode)
		if err := e.submitResult(ctx, c.ID, res); err != nil {
			slog.Warn("failed to submit command result", "command_id", c.ID, "error", err)
		}
	}
	return hint
}

// fetchPending asks the API for queued commands. The request body is HMAC-signed
// with the agent secret (same scheme as heartbeats) so the API can authenticate
// the agent, and marks the returned commands as dispatched server-side.
// It also returns the API's poll-cadence hint (0 when absent).
func (e *Executor) fetchPending(ctx context.Context) ([]pendingCommand, time.Duration, error) {
	body, _ := json.Marshal(map[string]string{"timestamp": time.Now().UTC().Format(time.RFC3339)})
	resp, err := e.signedPost(ctx, "/api/v1/agents/"+e.agentID+"/commands/poll", body)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("poll status %d", resp.StatusCode)
	}
	var out struct {
		Commands       []pendingCommand `json:"commands"`
		PollIntervalMs int              `json:"poll_interval_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, 0, err
	}
	return out.Commands, time.Duration(out.PollIntervalMs) * time.Millisecond, nil
}

// submitProgress pushes the output captured so far for a still-running
// command. Best-effort: an old API (404) or a blip just means the dashboard
// sees the output when the command finishes, as before.
func (e *Executor) submitProgress(ctx context.Context, commandID, stdout, stderr string) error {
	body, _ := json.Marshal(map[string]string{"stdout": stdout, "stderr": stderr})
	resp, err := e.signedPost(ctx, "/api/v1/agents/"+e.agentID+"/commands/"+commandID+"/progress", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("progress status %d", resp.StatusCode)
	}
	return nil
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
	req.Header.Set("X-Signature", sign(body, e.secretKey))
	req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	return e.client.Do(req)
}

func sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
