package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getopservo/opservo-agent/paths"
)

const legacyUnit = `[Unit]
Description=Opservo Agent

[Service]
EnvironmentFile=/etc/infrapilot/config
ExecStart=/usr/local/bin/infrapilot-agent
Restart=always
StateDirectory=infrapilot
`

const legacyConfig = `# Set to true, then:
#   systemctl restart infrapilot-agent
OPSERVO_API_URL=https://api.example.test
INFRAPILOT_AGENT_ID=old-id
OPSERVO_AGENT_ID=agent-1
INFRAPILOT_ENABLE_SHELL=true
OPSERVO_BUFFER_PATH=/var/lib/infrapilot/agent-buffer.db
`

// legacyBox lays out a pre-rename install under a temp root.
func legacyBox(t *testing.T) (*Migrator, string) {
	t.Helper()
	root := t.TempDir()
	write := func(p, s string, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(paths.LegacyUnitFile, legacyUnit, 0o644)
	write(paths.LegacyUnitFile+".d/override.conf", "[Service]\nEnvironment=X=1\n", 0o644)
	write(paths.LegacyConfigDir+"/config", legacyConfig, 0o600)
	write(paths.LegacyConfigDir+"/pg.conf", "postgres://ro@db/app\n", 0o600)
	write(paths.LegacyStateDir+"/agent-buffer.db", "sqlite", 0o644)
	write(paths.LegacyBinary, "binary", 0o755)
	return &Migrator{Root: root, Exe: filepath.Join(root, paths.LegacyBinary)}, root
}

func read(t *testing.T, root, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, p))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPrepareWritesNewLayout(t *testing.T) {
	m, root := legacyBox(t)
	if !m.Needed() {
		t.Fatal("a legacy box must need migrating")
	}
	if err := m.Prepare(); err != nil {
		t.Fatal(err)
	}

	unit := read(t, root, paths.UnitFile)
	for _, want := range []string{"EnvironmentFile=/etc/opservo/config", "ExecStart=/usr/local/bin/opservo-agent", "StateDirectory=opservo"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "infrapilot") {
		t.Errorf("unit still names the legacy layout:\n%s", unit)
	}
	if got := read(t, root, paths.UnitFile+".d/override.conf"); !strings.Contains(got, "X=1") {
		t.Errorf("drop-in not carried over: %q", got)
	}
	if got := read(t, root, paths.ConfigDir+"/pg.conf"); got != "postgres://ro@db/app\n" {
		t.Errorf("pg.conf changed: %q", got)
	}
	if got := read(t, root, paths.StateDir+"/agent-buffer.db"); got != "sqlite" {
		t.Errorf("buffer not copied: %q", got)
	}
	if got := read(t, root, paths.Binary); got != "binary" {
		t.Errorf("binary not copied: %q", got)
	}
	fi, err := os.Stat(filepath.Join(root, paths.ConfigDir, "config"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("config must stay root-only 0600, got %v %v", fi.Mode().Perm(), err)
	}
	// The legacy files stay until the new service is up.
	if read(t, root, paths.LegacyConfigDir+"/config") != legacyConfig {
		t.Error("legacy config must be left as it was")
	}
	if m.Needed() {
		t.Error("once the new unit exists the box must not migrate again")
	}
}

func TestRewriteConfig(t *testing.T) {
	got := RewriteConfig(legacyConfig)
	for _, want := range []string{
		"OPSERVO_AGENT_ID=agent-1",
		"OPSERVO_ENABLE_SHELL=true",
		"OPSERVO_BUFFER_PATH=/var/lib/opservo/agent-buffer.db",
		"systemctl restart opservo-agent",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "infrapilot") || strings.Contains(got, "INFRAPILOT") || strings.Contains(got, "old-id") {
		t.Errorf("legacy names left in:\n%s", got)
	}
}

func TestNeededOnlyForTheInstalledLegacyBinary(t *testing.T) {
	m, root := legacyBox(t)
	m.Exe = filepath.Join(root, "tmp/infrapilot-agent")
	if m.Needed() {
		t.Error("a copy run by hand from elsewhere must not rewire the box")
	}
}

func TestNotNeededAfterRollback(t *testing.T) {
	m, root := legacyBox(t)
	if err := os.WriteFile(filepath.Join(root, paths.LegacyStateDir, failedMarker), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if m.Needed() {
		t.Error("a rolled-back box must not retry on every start")
	}
}

func TestScriptRollsBackWhenTheNewServiceFails(t *testing.T) {
	s := Script()
	if !strings.Contains(s, "systemctl is-active --quiet "+paths.ServiceName) {
		t.Error("the switch must check the new service stays up")
	}
	ok, rollback, found := strings.Cut(s, "\nelse\n")
	if !found {
		t.Fatal("no rollback branch")
	}
	if !strings.Contains(ok, "rm -rf "+paths.LegacyUnitFile) || strings.Contains(rollback, paths.LegacyConfigDir) {
		t.Error("legacy files may only be removed once the new service is up")
	}
	if !strings.Contains(rollback, paths.ConfigDir) {
		t.Error("rollback must remove the copied config, or the legacy agent reads the copy")
	}
	if !strings.Contains(rollback, "systemctl start "+paths.LegacyServiceName) {
		t.Error("rollback must restart the legacy service")
	}
}
