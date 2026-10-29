package executor

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/getopservo/opservo-agent/paths"
)

// aptKeepConfigBody makes apt answer dpkg's "configuration file changed"
// question with "keep my current file" (and take the package's default when
// there is one). Founder decision, 29 Oct 2026: commands have no keyboard, so
// a package install must never stop on that question, and it must never
// overwrite the server's own config.
const aptKeepConfigBody = "// Written by the Opservo agent: dispatched commands keep current config files.\n" +
	"Dpkg::Options { \"--force-confdef\"; \"--force-confold\"; };\n"

// aptKeepConfigName is the file inside the agent's state directory.
const aptKeepConfigName = "apt-keep-config.conf"

// aptKeepConfig returns the path of the apt settings file for APT_CONFIG,
// writing it on first use, or "" when it cannot be used safely.
//
// apt reads APT_CONFIG as root, and apt configuration can run commands
// (APT::Update::Pre-Invoke), so the file must not be writable by anyone but
// the agent: it lives in the agent's own state directory, and only when that
// directory is owned by the agent's user and not group/world-writable. Never
// in /tmp.
func aptKeepConfig(dir string) string {
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm()&0o022 != 0 {
		return ""
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) != os.Geteuid() {
		return ""
	}
	p := filepath.Join(dir, aptKeepConfigName)
	if b, err := os.ReadFile(p); err == nil && string(b) == aptKeepConfigBody {
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	tmp, err := os.CreateTemp(dir, aptKeepConfigName+".*")
	if err != nil {
		return ""
	}
	_, werr := tmp.WriteString(aptKeepConfigBody)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Chmod(tmp.Name(), 0o644) != nil || os.Rename(tmp.Name(), p) != nil {
		_ = os.Remove(tmp.Name())
		return ""
	}
	return p
}

// withAptKeepConfig adds APT_CONFIG unless the environment already sets it.
func withAptKeepConfig(env []string, dir string) []string {
	if _, ok := lookupEnv(env, "APT_CONFIG"); ok {
		return env
	}
	if p := aptKeepConfig(dir); p != "" {
		return append(env, "APT_CONFIG="+p)
	}
	return env
}

func lookupEnv(env []string, key string) (string, bool) {
	val, ok := "", false
	for _, kv := range env {
		if len(kv) > len(key) && kv[:len(key)] == key && kv[len(key)] == '=' {
			val, ok = kv[len(key)+1:], true
		}
	}
	return val, ok
}

// stateDir is a variable so tests can point it at a temp directory.
var stateDir = paths.StateDir
