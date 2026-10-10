package updater

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// The embedded key must be a real 32-byte Ed25519 public key so signing is
// actually enforced — an empty/malformed constant would silently disable it.
func TestEmbeddedSigningKeyIsValid(t *testing.T) {
	pub, err := hex.DecodeString(signingPublicKeyHex)
	if err != nil {
		t.Fatalf("signingPublicKeyHex is not valid hex: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("signingPublicKeyHex must be %d bytes, got %d — update code-signing is DISABLED",
			ed25519.PublicKeySize, len(pub))
	}
}

func TestVerifyManifestSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil) // crypto/rand
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)
	manifest := []byte(`{"infrapilot-agent-linux-amd64":"deadbeef"}`)
	goodSig := hex.EncodeToString(ed25519.Sign(priv, manifest))

	if err := verifyManifestSignature(pubHex, manifest, goodSig); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}

	// Tampered manifest — same signature must NOT verify.
	if err := verifyManifestSignature(pubHex, []byte(`{"infrapilot-agent-linux-amd64":"eviii"}`), goodSig); err == nil {
		t.Error("tampered manifest accepted — signature check is not enforced")
	}

	// Signature from a different (attacker) key must be rejected.
	_, evilPriv, _ := ed25519.GenerateKey(nil)
	evilSig := hex.EncodeToString(ed25519.Sign(evilPriv, manifest))
	if err := verifyManifestSignature(pubHex, manifest, evilSig); err == nil {
		t.Error("signature from a foreign key accepted")
	}

	// Malformed inputs fail closed.
	if err := verifyManifestSignature("", manifest, goodSig); err == nil {
		t.Error("empty public key accepted")
	}
	if err := verifyManifestSignature(pubHex, manifest, "not-hex"); err == nil {
		t.Error("malformed signature accepted")
	}
}

func TestNeedsUpdate(t *testing.T) {
	manifest := map[string]string{
		"infrapilot-agent-linux-amd64": "aaa111",
		"infrapilot-agent-linux-arm64": "bbb222",
	}
	tests := []struct {
		name     string
		have     string
		asset    string
		wantSha  string
		wantBool bool
	}{
		{"up to date", "aaa111", "infrapilot-agent-linux-amd64", "aaa111", false},
		{"new build available", "old999", "infrapilot-agent-linux-amd64", "aaa111", true},
		{"different arch matched", "old999", "infrapilot-agent-linux-arm64", "bbb222", true},
		{"asset not advertised", "old999", "infrapilot-agent-linux-riscv", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, yes := NeedsUpdate(tt.have, manifest, tt.asset)
			if got != tt.wantSha || yes != tt.wantBool {
				t.Errorf("NeedsUpdate() = (%q, %v), want (%q, %v)", got, yes, tt.wantSha, tt.wantBool)
			}
		})
	}
}

func TestNew_DefaultsAndAsset(t *testing.T) {
	u := New("https://api.example.test/", 0)
	if u.interval != defaultInterval {
		t.Errorf("expected default interval, got %v", u.interval)
	}
	if u.apiURL != "https://api.example.test" {
		t.Errorf("trailing slash not trimmed: %q", u.apiURL)
	}
	if u.asset == "" || u.asset[:23] != "infrapilot-agent-linux-" {
		t.Errorf("unexpected asset name: %q", u.asset)
	}
}
