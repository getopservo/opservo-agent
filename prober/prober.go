// Package prober runs agent-based uptime checks: TCP connect-and-close probes
// against private-network targets (e.g. an RDS endpoint) that Opservo's cloud
// checkers cannot reach. STRICTLY opt-in per server (--enable-probes /
// OPSERVO_ENABLE_PROBES=true) — a fleet-wide agent update never makes a box
// probe anything, same guardrail as remote actions.
//
// Trust model: check assignments arrive in the heartbeat RESPONSE and are
// Ed25519-signed by the API (same keypair as command signing, distinct "probe"
// domain tag). When the embedded public key is set, the agent REFUSES any
// assignment whose signature doesn't verify — so neither DB write access nor a
// compromised API-adjacent process can retarget an opted-in agent's probes.
// The probe itself sends no bytes: dial, measure, close.
package prober

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// probeSigningPublicKeyHex verifies probe assignments. Same key as
// executor.commandSigningPublicKeyHex (the API signs both with one keypair,
// domain-separated); duplicated as its own const so the packages stay
// independent. An empty value would disable verification (same convention as
// command/update signing). A var so a per-environment build can link in its
// key (-ldflags "-X github.com/getopservo/opservo-agent/prober.probeSigningPublicKeyHex=…";
// api/Dockerfile sets it from the same COMMAND_SIGNING_PUBKEY build arg as the
// executor, so the two can't drift apart).
var probeSigningPublicKeyHex = "e1a4093b146bf6f33492aba76692362111b6abadeb8d46f90cd891fa9c4e1c7a"

// maxChecks mirrors the API-side MAX_PROBES_PER_AGENT cap — enforced here too
// so a malicious response can't turn the agent into a bulk scanner.
const maxChecks = 20

// Check is one probe assignment from the heartbeat response.
type Check struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Target    string `json:"target"` // host:port
	TimeoutMs int    `json:"timeout_ms"`
	Sig       string `json:"sig"` // hex Ed25519, "" if API signing is off
}

// Result is reported back inside the next heartbeat's data.check_results.
type Result struct {
	ID        string `json:"id"`
	Up        bool   `json:"up"`
	LatencyMs int    `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// Prober holds the latest results between heartbeats.
type Prober struct {
	agentID string
	pubKey  string
	mu      sync.Mutex
	results []Result
	// running is set while a probe run is in flight. A heartbeat that arrives
	// meanwhile starts nothing, so an older, slower run can never overwrite
	// the results of a newer one.
	running atomic.Bool
	// dial is runOne in production; tests swap it.
	dial func(Check) Result
}

func New(agentID string) *Prober {
	return &Prober{agentID: agentID, pubKey: probeSigningPublicKeyHex}
}

// signingMessage must match the Opservo API's
// probeSigningMessage byte-for-byte.
func signingMessage(agentID string, c Check) string {
	return "probe\n" + c.ID + "\n" + agentID + "\n" + c.Kind + "\n" + c.Target + "\n" + strconv.Itoa(c.TimeoutMs)
}

// verifySignature fails CLOSED on any malformed input; no-op when pubKeyHex is
// empty. Pure/parameterized (mirrors executor.verifyCommandSignature) for tests.
func verifySignature(pubKeyHex, agentID string, c Check) error {
	if pubKeyHex == "" {
		return nil
	}
	pub, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad embedded probe-signing public key")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(c.Sig))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("missing or malformed signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(signingMessage(agentID, c)), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// runOne performs a single TCP connect-and-close. It deliberately never sends
// a byte — reachability only.
func runOne(c Check) Result {
	timeout := time.Duration(c.TimeoutMs) * time.Millisecond
	if timeout < 500*time.Millisecond || timeout > 10*time.Second {
		timeout = 5 * time.Second
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", c.Target, timeout)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		msg := err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return Result{ID: c.ID, Up: false, LatencyMs: latency, Error: msg}
	}
	_ = conn.Close()
	return Result{ID: c.ID, Up: true, LatencyMs: latency}
}

// Run executes the checks handed back by the last heartbeat (asynchronously —
// results are stored and included in the NEXT heartbeat). An assignment with a
// bad signature is never dialed; it reports an explicit rejection instead so
// the tampering is visible on the dashboard rather than silently ignored.
//
// Single-flight: while a run is in progress a new one is skipped (returns
// false). The checks are dialed concurrently, so a run takes about one dial
// timeout (≤ 10 s) instead of up to 20 × 10 s — well inside the heartbeat
// interval even when every target black-holes SYNs.
func (p *Prober) Run(checks []Check) bool {
	if len(checks) > maxChecks {
		checks = checks[:maxChecks]
	}
	if !p.running.CompareAndSwap(false, true) {
		slog.Debug("probe run still in progress; skipping this one")
		return false
	}
	go func() {
		defer p.running.Store(false)
		results := p.runAll(checks)
		p.mu.Lock()
		p.results = results
		p.mu.Unlock()
	}()
	return true
}

// runAll verifies and dials every check concurrently; results keep the
// order of checks.
func (p *Prober) runAll(checks []Check) []Result {
	dial := p.dial
	if dial == nil {
		dial = runOne
	}
	results := make([]Result, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		if c.Kind != "tcp" {
			results[i] = Result{ID: c.ID, Up: false, Error: "unsupported check kind: " + c.Kind}
			continue
		}
		if err := verifySignature(p.pubKey, p.agentID, c); err != nil {
			slog.Error("REFUSING unsigned/invalid probe assignment", "monitor_id", c.ID, "target", c.Target, "error", err)
			results[i] = Result{ID: c.ID, Up: false, Error: "rejected: " + err.Error()}
			continue
		}
		slog.Debug("probing", "monitor_id", c.ID, "target", c.Target)
		wg.Add(1)
		go func(i int, c Check) {
			defer wg.Done()
			results[i] = dial(c)
		}(i, c)
	}
	wg.Wait()
	return results
}

// Drain returns the results collected since the last heartbeat and clears them.
func (p *Prober) Drain() []Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.results
	p.results = nil
	return r
}
