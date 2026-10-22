package updater

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	manifest := []byte(`{"opservo-agent-linux-amd64":"deadbeef"}`)
	goodSig := hex.EncodeToString(ed25519.Sign(priv, manifest))

	if err := verifyManifestSignature(pubHex, manifest, goodSig); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}

	// Tampered manifest — same signature must NOT verify.
	if err := verifyManifestSignature(pubHex, []byte(`{"opservo-agent-linux-amd64":"eviii"}`), goodSig); err == nil {
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
		"opservo-agent-linux-amd64": "aaa111",
		"opservo-agent-linux-arm64": "bbb222",
	}
	tests := []struct {
		name     string
		have     string
		asset    string
		wantSha  string
		wantBool bool
	}{
		{"up to date", "aaa111", "opservo-agent-linux-amd64", "aaa111", false},
		{"new build available", "old999", "opservo-agent-linux-amd64", "aaa111", true},
		{"different arch matched", "old999", "opservo-agent-linux-arm64", "bbb222", true},
		{"asset not advertised", "old999", "opservo-agent-linux-riscv", "", false},
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
	if u.asset == "" || u.asset[:20] != "opservo-agent-linux-" {
		t.Errorf("unexpected asset name: %q", u.asset)
	}
}

func TestCheckManifestFreshness(t *testing.T) {
	cases := []struct {
		name     string
		gen      string
		last     string
		wantLast string
		wantErr  bool
	}{
		{"no field, no state", "", "", "", false},
		{"no field keeps state", "", "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z", false},
		{"first accepted", "2026-10-15T10:00:00Z", "", "2026-10-15T10:00:00Z", false},
		{"newer accepted", "2026-10-16T10:00:00Z", "2026-10-15T10:00:00Z", "2026-10-16T10:00:00Z", false},
		{"equal accepted", "2026-10-15T10:00:00Z", "2026-10-15T10:00:00Z", "2026-10-15T10:00:00Z", false},
		{"normalised to UTC", "2026-10-15T15:30:00+05:30", "", "2026-10-15T10:00:00Z", false},
		{"older refused", "2026-10-14T10:00:00Z", "2026-10-15T10:00:00Z", "2026-10-15T10:00:00Z", true},
		{"malformed refused", "yesterday", "2026-10-15T10:00:00Z", "2026-10-15T10:00:00Z", true},
		{"corrupt state ignored", "2026-10-15T10:00:00Z", "garbage", "2026-10-15T10:00:00Z", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := map[string]string{"opservo-agent-linux-amd64": "abc"}
			if c.gen != "" {
				m["generated_at"] = c.gen
			}
			got, err := checkManifestFreshness(m, c.last)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if got != c.wantLast {
				t.Fatalf("persist value = %q, want %q", got, c.wantLast)
			}
		})
	}
}

func TestUpdater_StatePersistsAndRefusesRollback(t *testing.T) {
	dir := t.TempDir()
	u := New("https://api.example", 0).WithStateDir(dir)
	if u.readState() != "" {
		t.Fatal("fresh state dir must be empty")
	}
	if err := u.writeState("2026-10-15T10:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if got := u.readState(); got != "2026-10-15T10:00:00Z" {
		t.Fatalf("readState = %q", got)
	}
	// An older signed manifest replayed later must be refused using the
	// persisted value, a newer one accepted and persisted.
	if _, err := checkManifestFreshness(map[string]string{"generated_at": "2026-10-10T00:00:00Z"}, u.readState()); err == nil {
		t.Fatal("rollback not refused")
	}
	next, err := checkManifestFreshness(map[string]string{"generated_at": "2026-10-20T00:00:00Z"}, u.readState())
	if err != nil {
		t.Fatal(err)
	}
	if err := u.writeState(next); err != nil {
		t.Fatal(err)
	}
	if got := u.readState(); got != "2026-10-20T00:00:00Z" {
		t.Fatalf("state after accept = %q", got)
	}
	if New("x", 0).stateDir != "" {
		t.Fatal("anti-rollback must be off without a state dir")
	}
}

// A slow but steady download must finish even when it takes far longer than
// the stall timeout; only a download that stops sending bytes is abandoned.
func TestDownloadTo_SlowLinkSucceedsStallFails(t *testing.T) {
	old := downloadStallTimeout
	downloadStallTimeout = 150 * time.Millisecond
	defer func() { downloadStallTimeout = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		if r.URL.Path == "/download/stall" {
			_, _ = w.Write([]byte("x"))
			fl.Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		}
		for i := 0; i < 12; i++ { // ~600 ms in total, 4x the stall timeout
			_, _ = w.Write([]byte("chunk"))
			fl.Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()

	u := New(srv.URL, time.Hour)
	u.asset = "slow"
	if err := u.downloadTo(context.Background(), filepath.Join(dir, "slow")); err != nil {
		t.Fatalf("slow, steady download should succeed: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "slow")); len(b) != 60 {
		t.Fatalf("expected 60 bytes, got %d", len(b))
	}

	u.asset = "stall"
	start := time.Now()
	if err := u.downloadTo(context.Background(), filepath.Join(dir, "stall")); err == nil {
		t.Fatal("a stalled download must fail")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("stall was not detected promptly (%v)", time.Since(start))
	}
	if _, err := os.Stat(filepath.Join(dir, "stall")); !os.IsNotExist(err) {
		t.Fatal("a failed download must not leave a partial file")
	}
}

func TestOnce_CountsConsecutiveFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	u := New(srv.URL, time.Hour)
	for i := 1; i <= warnAfterFailures; i++ {
		u.once(context.Background())
		if u.failures != i {
			t.Fatalf("after %d failed checks, failures = %d", i, u.failures)
		}
	}
}
