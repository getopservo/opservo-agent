// Package updater lets the agent keep itself current with no manual re-install.
//
// On a schedule it fetches a content manifest from the API (sha256 of each
// served binary), compares it to the hash of its own running binary, and if the
// server advertises a different build it downloads + verifies + atomically swaps
// the binary and re-execs into it. The agent only ever pulls from its configured
// API over HTTPS and verifies the checksum the server advertises.
//
// Code-signing: when signingPublicKeyHex is set (it is), the agent
// Ed25519-verifies the manifest's signature before trusting any hash it lists —
// so a compromised distribution server alone cannot push a malicious build; it
// would also need the OFFLINE signing key. The manifest is signed at build time
// (AGENT_SIGNING_KEY, see cmd/sign); the private seed
// never reaches the running API. Verification fails CLOSED.
package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	defaultInterval = time.Hour
	initialDelay    = 90 * time.Second // first check shortly after start
)

// signingPublicKeyHex is the Ed25519 public key (64 hex chars) used to verify the
// update manifest's signature. It is set to Opservo's release key, so the
// agent REFUSES any update whose manifest isn't validly
// signed — so a compromised API alone can't push a malicious build (it would also
// need the offline signing key). Set it together with build-time signing
// (AGENT_SIGNING_KEY). An empty value disables verification — only do that
// for a private build that you sign some other way.
//
// It is a var, not a const, so a build for another environment can swap in
// that environment's key at link time without touching the source:
//
//	go build -ldflags "-X github.com/getopservo/opservo-agent/updater.signingPublicKeyHex=<64 hex>"
//
// (api/Dockerfile does this from the AGENT_SIGNING_PUBKEY build arg; staging
// has its own keypair so the production seed never has to sit on a box that
// also runs pull-request CI.)
var signingPublicKeyHex = "b7f1a9b29bd8ea7982a3e21b39a119ca4dbdfd065cf7bcdba486487d0bb0bc76"

type Updater struct {
	apiURL   string
	interval time.Duration
	client   *http.Client
	asset    string
	stateDir string // where the last accepted manifest timestamp is kept ("" = no anti-rollback)
}

// manifestStateFile (inside stateDir) holds the `generated_at` of the newest
// manifest this agent has accepted, so a replayed OLD signed manifest can't
// roll the fleet back to a signed-but-vulnerable build.
const manifestStateFile = "update-manifest.state"

func New(apiURL string, interval time.Duration) *Updater {
	if interval <= 0 {
		interval = defaultInterval
	}
	return &Updater{
		apiURL:   strings.TrimRight(apiURL, "/"),
		interval: interval,
		client:   &http.Client{Timeout: 90 * time.Second},
		asset:    "infrapilot-agent-linux-" + runtime.GOARCH,
	}
}

// WithStateDir enables anti-rollback: the newest accepted manifest
// `generated_at` is persisted in dir (same directory as the SQLite buffer) and
// any later manifest dated before it is refused. Missing field = allowed.
func (u *Updater) WithStateDir(dir string) *Updater {
	u.stateDir = strings.TrimSpace(dir)
	return u
}

// Run blocks, checking for updates shortly after start and then every interval.
// Intended to be launched in its own goroutine.
func (u *Updater) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(initialDelay):
	}
	u.once(ctx)

	ticker := time.NewTicker(u.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.once(ctx)
		}
	}
}

func (u *Updater) once(ctx context.Context) {
	if err := u.checkAndUpdate(ctx); err != nil {
		slog.Debug("auto-update check failed", "error", err)
	}
}

// NeedsUpdate reports the wanted sha and whether the running binary differs from
// what the server advertises for this asset. Pure, so it is unit-tested.
func NeedsUpdate(haveSha string, manifest map[string]string, asset string) (want string, yes bool) {
	want = manifest[asset]
	if want == "" || want == haveSha {
		return want, false
	}
	return want, true
}

// checkAndUpdate self-updates if the server has a different build. On success it
// re-execs and does not return; otherwise it returns (nil when already current).
func (u *Updater) checkAndUpdate(ctx context.Context) error {
	manifest, err := u.fetchManifest(ctx)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	have, err := sha256File(self)
	if err != nil {
		return err
	}
	want, yes := NeedsUpdate(have, manifest, u.asset)
	if !yes {
		return nil
	}

	slog.Info("new agent build available — updating", "have", short(have), "want", short(want))
	tmp := self + ".new"
	if err := u.downloadTo(ctx, tmp); err != nil {
		return err
	}
	got, err := sha256File(tmp)
	if err != nil || got != want {
		os.Remove(tmp)
		return fmt.Errorf("downloaded binary failed checksum verification")
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, self); err != nil { // atomic within the same filesystem
		os.Remove(tmp)
		return err
	}

	slog.Info("agent updated — restarting into the new build", "sha", short(want))
	// Replace this process image with the new binary; same PID, so systemd keeps
	// tracking the service without an ExecStart re-run.
	return syscall.Exec(self, os.Args, os.Environ())
}

func (u *Updater) fetchManifest(ctx context.Context) (map[string]string, error) {
	raw, err := u.fetchBytes(ctx, "/download/manifest.json", 1<<16)
	if err != nil {
		return nil, err
	}
	// When signing is configured, the manifest must carry a valid signature over
	// these exact bytes before we trust any hash it advertises.
	if signingPublicKeyHex != "" {
		if err := u.verifyManifestSig(ctx, raw); err != nil {
			return nil, fmt.Errorf("manifest signature check failed (refusing update): %w", err)
		}
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	// Anti-rollback: a signature proves the manifest is OURS, not that it is
	// CURRENT. Refuse one older than the newest we have already accepted.
	if u.stateDir != "" {
		last := u.readState()
		accepted, err := checkManifestFreshness(m, last)
		if err != nil {
			slog.Warn("refusing update manifest", "error", err)
			return nil, err
		}
		if accepted != last {
			if err := u.writeState(accepted); err != nil {
				slog.Warn("could not persist accepted manifest timestamp", "error", err)
			}
		}
	}
	return m, nil
}

// checkManifestFreshness compares the manifest's optional `generated_at`
// (RFC 3339) with the last accepted value and returns the value to persist.
// Pure, so it is unit-tested. Rules: no field → allowed, state unchanged
// (backward compatible with manifests built before the field existed); a
// malformed field → refused (our own build emitted it, so fail loudly); an
// unreadable persisted value is ignored and overwritten; older than persisted →
// refused; equal or newer → accepted.
func checkManifestFreshness(m map[string]string, last string) (string, error) {
	gen := strings.TrimSpace(m["generated_at"])
	if gen == "" {
		return last, nil
	}
	t, err := time.Parse(time.RFC3339, gen)
	if err != nil {
		return last, fmt.Errorf("manifest generated_at %q is not RFC 3339: %w", gen, err)
	}
	if lt, lerr := time.Parse(time.RFC3339, strings.TrimSpace(last)); lerr == nil && t.Before(lt) {
		return last, fmt.Errorf("manifest generated_at %s is older than the last accepted %s — possible rollback", t.UTC().Format(time.RFC3339), lt.UTC().Format(time.RFC3339))
	}
	return t.UTC().Format(time.RFC3339), nil
}

func (u *Updater) readState() string {
	b, err := os.ReadFile(filepath.Join(u.stateDir, manifestStateFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeState persists the accepted timestamp atomically (tmp + rename).
func (u *Updater) writeState(v string) error {
	if err := os.MkdirAll(u.stateDir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(u.stateDir, manifestStateFile)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, []byte(v+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// verifyManifestSig fetches /download/manifest.json.sig and Ed25519-verifies it
// against the raw manifest bytes using the embedded public key.
func (u *Updater) verifyManifestSig(ctx context.Context, manifest []byte) error {
	sigHex, err := u.fetchBytes(ctx, "/download/manifest.json.sig", 4096)
	if err != nil {
		return fmt.Errorf("missing signature: %w", err)
	}
	return verifyManifestSignature(signingPublicKeyHex, manifest, string(sigHex))
}

// verifyManifestSignature Ed25519-verifies sigHex (hex) over manifest using the
// hex-encoded public key. Pure, so it is unit-tested. Fails closed on any bad
// input (malformed key/signature or a signature that doesn't match).
func verifyManifestSignature(pubKeyHex string, manifest []byte, sigHex string) error {
	pub, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad embedded signing public key")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("bad signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), manifest, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (u *Updater) fetchBytes(ctx context.Context, path string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.apiURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s status %d", path, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func (u *Updater) downloadTo(ctx context.Context, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.apiURL+"/download/"+u.asset, nil)
	if err != nil {
		return err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download status %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		os.Remove(dst)
		return copyErr
	}
	return closeErr
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
