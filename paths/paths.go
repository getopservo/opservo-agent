// Package paths names the agent's on-disk layout in one place.
//
// The installer (scripts/install.sh) writes the same paths; keep them in step.
package paths

import "path/filepath"

const (
	ConfigDir   = "/etc/opservo"
	StateDir    = "/var/lib/opservo"
	Binary      = "/usr/local/bin/opservo-agent"
	ServiceName = "opservo-agent.service"
	UnitFile    = "/etc/systemd/system/" + ServiceName
)

// ConfigFile returns the path of a file in the agent's config directory
// (config, mysql.cnf, pg.conf).
func ConfigFile(name string) string {
	return filepath.Join(ConfigDir, name)
}
