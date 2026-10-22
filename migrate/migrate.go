// Package migrate moves a box installed before the rename onto the current
// on-disk layout (see the paths package), once, on the first start of a new
// build. A legacy agent picks up a new build through the self-updater, so the
// whole fleet moves with no re-install and keeps its agent ID and secret.
//
// It copies the config directory (rewriting legacy key names and paths), the
// state directory and the running binary to the new paths, writes the new
// systemd unit from the legacy one, then hands the switch to a transient
// systemd unit: stopping the legacy service stops this process, so the switch
// cannot run inside it. That unit starts the new service and, once it stays
// up, removes the legacy files; if it does not come up it puts the legacy
// service back, removes the copies (so the legacy agent keeps reading its own
// files) and leaves a marker so the next start does not retry.
//
// Remove this package once no installed agent reports from the legacy layout.
package migrate

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/getopservo/opservo-agent/paths"
)

// failedMarker (in the legacy state dir) is left by a rolled-back switch.
const failedMarker = "opservo-migration-failed"

// legacyRefs rewrites legacy paths and names inside the config file, the
// unit file and its drop-ins.
var legacyRefs = strings.NewReplacer(
	paths.LegacyConfigDir, paths.ConfigDir,
	paths.LegacyStateDir, paths.StateDir,
	"StateDirectory=infrapilot", "StateDirectory=opservo",
	"infrapilot-agent", "opservo-agent",
)

// Migrator does the work under Root ("" on a real box; a temp dir in tests).
type Migrator struct {
	Root string
	// Exe is the running binary. Only the legacy installed binary migrates,
	// so a copy run by hand from elsewhere never rewires the box.
	Exe string
	// HandOff runs the switch script outside this service.
	HandOff func(script string) error
}

func (m *Migrator) p(path string) string { return filepath.Join(m.Root, path) }

// Needed reports whether this box is on the legacy layout and can be moved.
func (m *Migrator) Needed() bool {
	if m.Exe != m.p(paths.LegacyBinary) {
		return false
	}
	return exists(m.p(paths.LegacyUnitFile)) &&
		exists(m.p(filepath.Join(paths.LegacyConfigDir, "config"))) &&
		!exists(m.p(paths.UnitFile)) &&
		!exists(m.p(filepath.Join(paths.LegacyStateDir, failedMarker)))
}

// Prepare writes the new layout next to the legacy one. The legacy files are
// untouched, so the box keeps running on them if anything here fails. The
// new unit is written last: its presence is what marks the copy complete.
func (m *Migrator) Prepare() error {
	if err := copyTree(m.p(paths.LegacyConfigDir), m.p(paths.ConfigDir), func(rel string, b []byte) []byte {
		if rel == "config" {
			return []byte(RewriteConfig(string(b)))
		}
		return b
	}); err != nil {
		return fmt.Errorf("migrate: config dir: %w", err)
	}
	if exists(m.p(paths.LegacyStateDir)) {
		if err := copyTree(m.p(paths.LegacyStateDir), m.p(paths.StateDir), nil); err != nil {
			return fmt.Errorf("migrate: state dir: %w", err)
		}
	}
	if err := copyFile(m.Exe, m.p(paths.Binary), 0o755, nil); err != nil {
		return fmt.Errorf("migrate: binary: %w", err)
	}
	legacyDropIns := m.p(paths.LegacyUnitFile + ".d")
	if exists(legacyDropIns) {
		if err := copyTree(legacyDropIns, m.p(paths.UnitFile+".d"), func(_ string, b []byte) []byte {
			return []byte(legacyRefs.Replace(string(b)))
		}); err != nil {
			return fmt.Errorf("migrate: unit drop-ins: %w", err)
		}
	}
	unit, err := os.ReadFile(m.p(paths.LegacyUnitFile))
	if err != nil {
		return fmt.Errorf("migrate: read unit: %w", err)
	}
	if err := writeAtomic(m.p(paths.UnitFile), []byte(legacyRefs.Replace(string(unit))), 0o644); err != nil {
		return fmt.Errorf("migrate: write unit: %w", err)
	}
	return nil
}

// Script is the switch the transient unit runs. The new service must still
// be active 15 s after starting (Restart=always would otherwise hide a crash
// loop) before the legacy files go.
func Script() string {
	return strings.Join([]string{
		"systemctl daemon-reload",
		"systemctl enable " + paths.ServiceName,
		"systemctl stop " + paths.LegacyServiceName,
		"if systemctl start " + paths.ServiceName + " && sleep 15 && systemctl is-active --quiet " + paths.ServiceName + "; then",
		"  systemctl disable " + paths.LegacyServiceName,
		"  rm -rf " + strings.Join([]string{paths.LegacyUnitFile, paths.LegacyUnitFile + ".d", paths.LegacyBinary, paths.LegacyConfigDir, paths.LegacyStateDir}, " "),
		"  systemctl daemon-reload",
		"else",
		"  systemctl disable " + paths.ServiceName,
		"  systemctl stop " + paths.ServiceName,
		"  rm -rf " + strings.Join([]string{paths.UnitFile, paths.UnitFile + ".d", paths.Binary, paths.ConfigDir, paths.StateDir}, " "),
		"  mkdir -p " + paths.LegacyStateDir + " && touch " + filepath.Join(paths.LegacyStateDir, failedMarker),
		"  systemctl daemon-reload",
		"  systemctl start " + paths.LegacyServiceName,
		"fi",
	}, "\n")
}

// RewriteConfig renames legacy INFRAPILOT_* keys to OPSERVO_* (dropping one
// whose OPSERVO_* twin is already set) and rewrites legacy paths. Pure, so it
// is unit-tested.
func RewriteConfig(s string) string {
	have := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		if k, _, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.HasPrefix(k, "OPSERVO_") {
			have[k] = true
		}
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if k, v, ok := strings.Cut(trimmed, "="); ok && strings.HasPrefix(k, "INFRAPILOT_") {
			nk := "OPSERVO_" + strings.TrimPrefix(k, "INFRAPILOT_")
			if have[nk] {
				continue
			}
			have[nk] = true
			line = nk + "=" + v
		}
		out = append(out, legacyRefs.Replace(line))
	}
	return strings.Join(out, "\n")
}

// Run moves this box if it is on the legacy layout. It returns true once the
// switch has been handed off: the caller should then wait to be stopped.
func Run() bool {
	if os.Geteuid() != 0 || !exists("/run/systemd/system") {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	m := &Migrator{Exe: exe, HandOff: systemdRun}
	if !m.Needed() {
		return false
	}
	slog.Info("moving this agent to the current install layout", "config", paths.ConfigDir, "service", paths.ServiceName)
	if err := m.Prepare(); err != nil {
		os.Remove(paths.UnitFile) // so the next start tries again from scratch
		slog.Warn("could not move to the current install layout — staying on the old one", "error", err)
		return false
	}
	if err := m.HandOff(Script()); err != nil {
		os.Remove(paths.UnitFile)
		slog.Warn("could not hand over to the new service — staying on the old one", "error", err)
		return false
	}
	return true
}

// systemdRun starts the script as its own transient unit, outside this
// service's cgroup, so stopping this service does not stop the script.
func systemdRun(script string) error {
	unit := "opservo-agent-migrate-" + strconv.FormatInt(time.Now().Unix(), 10)
	out, err := exec.Command("systemd-run", "--unit="+unit, "--quiet", "/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// copyTree copies regular files under src to dst, keeping modes; transform
// (if set) rewrites each file's content by its path relative to src.
func copyTree(src, dst string, transform func(rel string, b []byte) []byte) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
		return err
	}
	return filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil || rel == "." {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case fi.IsDir():
			return os.MkdirAll(target, fi.Mode().Perm())
		case fi.Mode().IsRegular():
			var tf func([]byte) []byte
			if transform != nil {
				tf = func(b []byte) []byte { return transform(rel, b) }
			}
			return copyFile(path, target, fi.Mode().Perm(), tf)
		}
		return nil // sockets, symlinks: nothing the agent keeps there
	})
}

func copyFile(src, dst string, mode os.FileMode, transform func([]byte) []byte) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if transform != nil {
		b = transform(b)
	}
	return writeAtomic(dst, b, mode)
}

func writeAtomic(dst string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".migrate.tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
