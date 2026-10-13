// Package shell runs live terminal sessions (B-6) opened from the Opservo
// dashboard: a PTY running the chosen user's login shell, streamed over a
// WebSocket the agent dials OUT to the API.
//
// SECURITY: off unless the operator sets OPSERVO_ENABLE_SHELL=true on this
// server (default false — stricter than remote actions). Even then a session
// only starts when the API hands over a start that verifies against the
// embedded command-signing public key and hasn't expired; the API in turn
// only issues one when the server's dashboard switch is on and an
// owner/admin confirmed their identity. See docs/live-terminal.md.
package shell

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Start is a session the API asks this agent to open, as delivered in the
// command-poll response.
type Start struct {
	ID        string `json:"id"`
	OSUser    string `json:"os_user"`
	ExpiresAt string `json:"expires_at"` // exact string the API signed (RFC 3339, UTC)
	Signature string `json:"signature"`  // hex Ed25519
}

// startMessage is the exact byte sequence the API signs — must match
// shellStartMessage in the Opservo API byte-for-byte. The "shell" domain tag
// keeps it from ever being valid as a command ("<uuid>\n…"), probe
// ("probe\n…") or cancel ("cancel\n…") signature.
func startMessage(agentID string, s Start) string {
	return "shell\n" + s.ID + "\n" + agentID + "\n" + s.OSUser + "\n" + s.ExpiresAt
}

// VerifyStart checks a session start: signature over the start message with
// pubKeyHex, and not expired at `now`. Unlike command signing, an empty
// public key does NOT disable the check — a live shell is never opened on an
// unsigned request.
func VerifyStart(pubKeyHex, agentID string, s Start, now time.Time) error {
	pub, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("no valid signing key embedded; live terminal unavailable")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(s.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("missing or malformed signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(startMessage(agentID, s)), sig) {
		return fmt.Errorf("signature verification failed")
	}
	exp, err := time.Parse(time.RFC3339Nano, s.ExpiresAt)
	if err != nil {
		return fmt.Errorf("bad expiry %q", s.ExpiresAt)
	}
	if !now.Before(exp) {
		return fmt.Errorf("session start expired at %s", s.ExpiresAt)
	}
	if s.OSUser == "" || strings.ContainsAny(s.OSUser, "\n/: ") {
		return fmt.Errorf("bad user name")
	}
	return nil
}
