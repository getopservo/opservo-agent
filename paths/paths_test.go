package paths

import (
	"path/filepath"
	"testing"
)

func TestConfigFileDefaultsToNewDir(t *testing.T) {
	// Neither directory exists in the test sandbox for a made-up name.
	got := ConfigFile("no-such-file-for-test.conf")
	if want := filepath.Join(ConfigDir, "no-such-file-for-test.conf"); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}
