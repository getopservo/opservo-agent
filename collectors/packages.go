package collectors

import (
	"context"
	"strconv"
	"strings"
)

// InstalledPkg is one installed package and its on-disk size (KB).
type InstalledPkg struct {
	Package string `json:"package"`
	SizeKB  int    `json:"size_kb"`
}

// PackagesInfo: upgradable packages and the biggest installed ones, collected
// each heartbeat (apt/dpkg only — Available is false on non-Debian systems).
type PackagesInfo struct {
	Available    bool           `json:"available"`
	Upgradable   []string       `json:"upgradable"`
	InstalledTop []InstalledPkg `json:"installed_top"`
}

type PackagesCollector struct{}

func NewPackagesCollector() *PackagesCollector { return &PackagesCollector{} }
func (p *PackagesCollector) Name() string      { return "packages" }

func (p *PackagesCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &PackagesInfo{Upgradable: []string{}, InstalledTop: []InstalledPkg{}}
	if !hasBinary("dpkg-query") {
		return info, nil // not a Debian/Ubuntu system
	}
	info.Available = true

	// Upgradable (reads the local apt cache only — no network apt-get update).
	// Shared with the updates collector so `apt list` runs once per cycle;
	// the "Listing…" header line is filtered here instead of via a grep subshell.
	if out, err := sharedAptUpgradable(ctx); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Listing") {
				continue
			}
			name := strings.SplitN(line, "/", 2)[0]
			if name != "" {
				info.Upgradable = append(info.Upgradable, name)
			}
		}
	}

	// Largest installed packages by size.
	if out, err := runCmd(ctx, "sh", "-c", "dpkg-query -Wf '${Installed-Size}\\t${Package}\\n' 2>/dev/null | sort -rn | head -40"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) != 2 {
				continue
			}
			if size, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
				info.InstalledTop = append(info.InstalledTop, InstalledPkg{Package: strings.TrimSpace(parts[1]), SizeKB: size})
			}
		}
	}
	return info, nil
}
