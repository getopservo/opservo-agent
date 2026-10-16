package executor

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// The embedded key must be a real 32-byte Ed25519 public key, or command
// signature verification is silently disabled.
func TestEmbeddedCommandSigningKeyIsValid(t *testing.T) {
	pub, err := hex.DecodeString(commandSigningPublicKeyHex)
	if err != nil {
		t.Fatalf("commandSigningPublicKeyHex is not valid hex: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("commandSigningPublicKeyHex must be %d bytes, got %d — command signing is DISABLED",
			ed25519.PublicKeySize, len(pub))
	}
}

func TestVerifyCommandSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)
	c := pendingCommand{ID: "cmd-1", Command: "uptime", ExpiresAt: "2026-01-01T00:10:00.000Z"}
	msg := c.ID + "\n" + "agent-1" + "\n" + c.Command + "\n" + c.ExpiresAt
	c.Signature = hex.EncodeToString(ed25519.Sign(priv, []byte(msg)))

	if err := verifyCommandSignature(pubHex, "agent-1", c); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}

	// Wrong agent (cross-agent replay) must NOT verify.
	if err := verifyCommandSignature(pubHex, "agent-2", c); err == nil {
		t.Error("signature verified for the wrong agent_id — cross-agent replay is possible")
	}

	// Tampered command text must NOT verify.
	tampered := c
	tampered.Command = "rm -rf /"
	if err := verifyCommandSignature(pubHex, "agent-1", tampered); err == nil {
		t.Error("tampered command accepted — signature check is not enforced")
	}

	// Signature from a foreign (attacker) key must be rejected.
	_, evilPriv, _ := ed25519.GenerateKey(nil)
	evil := c
	evil.Signature = hex.EncodeToString(ed25519.Sign(evilPriv, []byte(msg)))
	if err := verifyCommandSignature(pubHex, "agent-1", evil); err == nil {
		t.Error("signature from a foreign key accepted")
	}

	// Malformed inputs fail closed.
	if err := verifyCommandSignature(pubHex, "agent-1", pendingCommand{ID: c.ID, Command: c.Command, ExpiresAt: c.ExpiresAt, Signature: "not-hex"}); err == nil {
		t.Error("malformed signature accepted")
	}
	if err := verifyCommandSignature(pubHex, "agent-1", pendingCommand{ID: c.ID, Command: c.Command, ExpiresAt: c.ExpiresAt}); err == nil {
		t.Error("empty signature accepted")
	}

	// Empty pubKeyHex = verification disabled entirely (pre-rollout state) — a
	// missing/garbage signature must NOT block execution in that mode.
	if err := verifyCommandSignature("", "agent-1", pendingCommand{ID: c.ID, Command: c.Command}); err != nil {
		t.Errorf("verification should be a no-op when no public key is configured: %v", err)
	}
}

// Cross-language interop: this signature+message pair was produced by the
// REAL TypeScript signer in the Opservo API (signCommand) against
// a matching Ed25519 test keypair — not fabricated in Go. Proves the two
// implementations agree on the exact bytes being signed.
func TestVerifyCommandSignature_InteropWithTypeScriptSigner(t *testing.T) {
	// Public key derived (via Node crypto) from seed
	// 480051225231f7226d2fdc5cc673d868822160f168cda6314e193d884c23e8eb.
	const pubHex = "1d53ae157ea41fc42412ffa3d865cce96cd1b57441bdde097c91f00dea5b217e"
	c := pendingCommand{
		ID:        "cmd-xlang",
		Command:   "echo interop",
		ExpiresAt: "2026-01-01T00:10:00.000Z",
		Signature: "d23034d19ccd836b925563cf6394a07c29a053855beffa0587435eb3648b0e0c67f54a8068c7353e781af28d2b44a0ca8ca4c862f2049e3e85f9edbf599d050e",
	}
	if err := verifyCommandSignature(pubHex, "agent-xlang", c); err != nil {
		t.Fatalf("TypeScript-produced signature did not verify in Go: %v", err)
	}
}

// The API's signCancel (api/src/lib/commandSigning.test.ts "cancelSigning")
// produces exactly this signature with the same test seed as the command
// interop test above. Change both together or never.
func TestVerifyCancelSignature_InteropWithTypeScriptSigner(t *testing.T) {
	const pubHex = "1d53ae157ea41fc42412ffa3d865cce96cd1b57441bdde097c91f00dea5b217e"
	const sig = "cf03dccc6d98e9a4fc04856fe273a7cfd30e14cf41ea372e70f5ed0ad960dc142fb245502648aa68606f4d00bf8ccf8ef858179e507e770756804c4a4c9fa207"
	const cmdID = "11111111-2222-3333-4444-555555555555"
	if err := verifyCancelSignature(pubHex, "agent-1", cmdID, sig); err != nil {
		t.Fatalf("TypeScript-produced cancel signature did not verify in Go: %v", err)
	}
	// Bound to one command on one agent.
	if verifyCancelSignature(pubHex, "agent-2", cmdID, sig) == nil {
		t.Error("cancel for agent-1 verified for agent-2")
	}
	if verifyCancelSignature(pubHex, "agent-1", "99999999-2222-3333-4444-555555555555", sig) == nil {
		t.Error("cancel for one command verified for another")
	}
	if verifyCancelSignature(pubHex, "agent-1", cmdID, "") == nil {
		t.Error("empty signature accepted")
	}
	// A cancel signature is not a valid command signature (domain separation).
	c := pendingCommand{ID: "cancel", Command: cmdID, ExpiresAt: "agent-1", Signature: sig}
	if verifyCommandSignature(pubHex, "x", c) == nil {
		t.Error("cancel signature accepted as a command signature")
	}
}

// A valid signature on a command whose expires_at has passed must still be
// refused (same fixture as the interop test: the TypeScript signer signed
// expires_at 2026-01-01T00:10:00.000Z, which is now in the past).
func TestCheckCommandExpiry_RefusesExpiredSignedCommand(t *testing.T) {
	const pubHex = "1d53ae157ea41fc42412ffa3d865cce96cd1b57441bdde097c91f00dea5b217e"
	c := pendingCommand{
		ID:        "cmd-xlang",
		Command:   "echo interop",
		ExpiresAt: "2026-01-01T00:10:00.000Z",
		Signature: "d23034d19ccd836b925563cf6394a07c29a053855beffa0587435eb3648b0e0c67f54a8068c7353e781af28d2b44a0ca8ca4c862f2049e3e85f9edbf599d050e",
	}
	if err := verifyCommandSignature(pubHex, "agent-xlang", c); err != nil {
		t.Fatalf("fixture signature no longer verifies: %v", err)
	}
	if err := checkCommandExpiry(c, time.Now()); err == nil {
		t.Error("expired command accepted")
	} else if !strings.Contains(err.Error(), "command expired") {
		t.Errorf("reason should say the command expired, got %q", err)
	}
	// Still accepted while the deadline is ahead.
	if err := checkCommandExpiry(c, time.Date(2026, 1, 1, 0, 9, 59, 0, time.UTC)); err != nil {
		t.Errorf("unexpired command refused: %v", err)
	}
	// Exactly at the deadline is expired (not before).
	if checkCommandExpiry(c, time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC)) == nil {
		t.Error("command at its deadline accepted")
	}
	// The API always sets expires_at, so empty/garbage is refused, never run.
	for _, bad := range []string{"", "soon", "2026-01-01"} {
		if checkCommandExpiry(pendingCommand{ExpiresAt: bad}, time.Now()) == nil {
			t.Errorf("expires_at %q accepted", bad)
		}
	}
}
