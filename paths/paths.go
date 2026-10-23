// Package paths names the agent's on-disk layout in one place.
//
// The installer (scripts/install.sh) writes the same paths; keep them in step.
// Agents installed before the rename used an older layout (Legacy*). The
// migrate package moves such a box over on its first start of a new build;
// the Legacy* names exist only so a box that has not moved yet keeps working.
package paths

import (
	"os"
	"path/filepath"
)

const (
	ConfigDir   = "/etc/opservo"
	StateDir    = "/var/lib/opservo"
	Binary      = "/usr/local/bin/opservo-agent"
	ServiceName = "opservo-agent.service"
	UnitFile    = "/etc/systemd/system/" + ServiceName

	// Pre-rename layout. Remove together with the migrate package once no
	// installed agent reports from it.
	LegacyConfigDir   = "/etc/infrapilot"
	LegacyStateDir    = "/var/lib/infrapilot"
	LegacyBinary      = "/usr/local/bin/infrapilot-agent"
	LegacyServiceName = "infrapilot-agent.service"
	LegacyUnitFile    = "/etc/systemd/system/" + LegacyServiceName
)

// ConfigFile returns the path of a file in the agent's config directory
// (config, mysql.cnf, pg.conf). It is the new directory unless only the
// legacy one has the file, so a box that has not migrated keeps reading it.
func ConfigFile(name string) string {
	p := filepath.Join(ConfigDir, name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if lp := filepath.Join(LegacyConfigDir, name); fileExists(lp) {
		return lp
	}
	return p
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
