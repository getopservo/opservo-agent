package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAptKeepConfigWritesInAPrivateStateDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := aptKeepConfig(dir)
	if p != filepath.Join(dir, aptKeepConfigName) {
		t.Fatalf("path = %q", p)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"--force-confdef"; "--force-confold";`) {
		t.Fatalf("body = %q", b)
	}
	// A tampered file is put back.
	if err := os.WriteFile(p, []byte(`APT::Update::Pre-Invoke { "touch /tmp/pwned"; };`), 0o644); err != nil {
		t.Fatal(err)
	}
	if aptKeepConfig(dir) != p {
		t.Fatal("expected the file to be rewritten")
	}
	if b, _ := os.ReadFile(p); string(b) != aptKeepConfigBody {
		t.Fatalf("tampered body kept: %q", b)
	}
}

func TestAptKeepConfigRefusesUnsafeDirs(t *testing.T) {
	writable := t.TempDir()
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if p := aptKeepConfig(writable); p != "" {
		t.Fatalf("world-writable dir accepted: %q", p)
	}
	if p := aptKeepConfig(filepath.Join(t.TempDir(), "missing")); p != "" {
		t.Fatalf("missing dir accepted: %q", p)
	}
	real := t.TempDir()
	_ = os.Chmod(real, 0o755)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if p := aptKeepConfig(link); p != "" {
		t.Fatalf("symlinked dir accepted: %q", p)
	}
}

func TestWithAptKeepConfigKeepsTheCallersOwnSetting(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	env := withAptKeepConfig([]string{"APT_CONFIG=/etc/mine.conf"}, dir)
	if v, _ := lookupEnv(env, "APT_CONFIG"); v != "/etc/mine.conf" {
		t.Fatalf("APT_CONFIG = %q", v)
	}
	env = withAptKeepConfig([]string{"PATH=/usr/bin"}, dir)
	if v, _ := lookupEnv(env, "APT_CONFIG"); v != filepath.Join(dir, aptKeepConfigName) {
		t.Fatalf("APT_CONFIG = %q", v)
	}
}

func TestCommandsGetNoPromptPackageDefaults(t *testing.T) {
	old := stateDir
	stateDir = t.TempDir()
	_ = os.Chmod(stateDir, 0o755)
	defer func() { stateDir = old }()
	res := runCommand(context.Background(), `echo "$NEEDRESTART_MODE $UCF_FORCE_CONFFOLD $APT_LISTCHANGES_FRONTEND $DEBIAN_FRONTEND"; cat "$APT_CONFIG"`, nil, 10*time.Second)
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: %s", res.ExitCode, res.Stderr)
	}
	if !strings.HasPrefix(res.Stdout, "a 1 none noninteractive\n") || !strings.Contains(res.Stdout, "--force-confold") {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}
