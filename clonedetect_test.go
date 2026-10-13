package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsClone(t *testing.T) {
	cases := []struct {
		recorded, current string
		want              bool
	}{
		{"i-aaa", "i-bbb", true},
		{"i-aaa", "i-aaa", false},
		{"", "i-bbb", false}, // no recorded identity (old installer) — never a clone
		{"i-aaa", "", false}, // can't read identity now — don't re-register on a flake
		{"", "", false},
	}
	for _, c := range cases {
		if got := isClone(c.recorded, c.current); got != c.want {
			t.Errorf("isClone(%q, %q) = %v, want %v", c.recorded, c.current, got, c.want)
		}
	}
}

func TestRewriteConfigIdentity(t *testing.T) {
	in := `# Opservo agent configuration — managed by the installer.
OPSERVO_API_URL=https://api.getopservo.com
OPSERVO_AGENT_ID=old-id
OPSERVO_SECRET_KEY=old-secret
OPSERVO_MACHINE_ID=i-old
OPSERVO_BUFFER_PATH=/var/lib/infrapilot/buffer.db
OPSERVO_ENROLL_KEY=fleet_abc
`
	out := rewriteConfigIdentity(in, "new-id", "new-secret", "i-new")
	for _, want := range []string{
		"OPSERVO_AGENT_ID=new-id",
		"OPSERVO_SECRET_KEY=new-secret",
		"OPSERVO_MACHINE_ID=i-new",
		"OPSERVO_API_URL=https://api.getopservo.com", // untouched
		"OPSERVO_ENROLL_KEY=fleet_abc",               // fleet key survives for the NEXT clone
		"OPSERVO_BUFFER_PATH=/var/lib/infrapilot/buffer.db",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rewritten config missing %q:\n%s", want, out)
		}
	}
	for _, gone := range []string{"old-id", "old-secret", "i-old"} {
		if strings.Contains(out, gone) {
			t.Errorf("rewritten config still contains %q:\n%s", gone, out)
		}
	}
}

func TestRewriteConfigIdentityAppendsMissingAndDropsLegacy(t *testing.T) {
	// A config from an older installer: no machine id, legacy INFRAPILOT_* creds.
	in := "OPSERVO_API_URL=https://api.getopservo.com\nINFRAPILOT_AGENT_ID=legacy\nINFRAPILOT_SECRET_KEY=legacy-secret\n"
	out := rewriteConfigIdentity(in, "new-id", "new-secret", "i-new")
	for _, want := range []string{"OPSERVO_AGENT_ID=new-id", "OPSERVO_SECRET_KEY=new-secret", "OPSERVO_MACHINE_ID=i-new"} {
		if !strings.Contains(out, want) {
			t.Errorf("rewritten config missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "INFRAPILOT_AGENT_ID") || strings.Contains(out, "legacy-secret") {
		t.Errorf("legacy credential lines should be dropped:\n%s", out)
	}
}

func TestPersistIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("OPSERVO_AGENT_ID=old\nOPSERVO_SECRET_KEY=olds\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistIdentity(path, "nid", "nkey", "i-x"); err != nil {
		t.Fatalf("persistIdentity: %v", err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "OPSERVO_AGENT_ID=nid") || !strings.Contains(string(data), "OPSERVO_MACHINE_ID=i-x") {
		t.Errorf("config not rewritten: %s", data)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v, want 0600", info.Mode().Perm())
	}
}
