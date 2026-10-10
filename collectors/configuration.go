package collectors

import (
	"context"
	"strings"
	"time"
)

// ConfigurationCollector reports host-configuration facts that OHS Configuration
// rules consume. v1: NTP time-sync and whether swap is configured. Duplicate-IP
// and hugepage tuning are intentionally left to a later pass (arping is noisy /
// needs root; hugepage "correctness" is workload-dependent → low confidence).
//
// JSON key: "configuration" → snapshot.configuration.
type ConfigurationCollector struct{}

func NewConfigurationCollector() *ConfigurationCollector { return &ConfigurationCollector{} }
func (c *ConfigurationCollector) Name() string           { return "configuration" }

type ConfigurationReport struct {
	TimeSynchronized *bool     `json:"time_synchronized,omitempty"` // nil if timedatectl absent
	SwapConfigured   bool      `json:"swap_configured"`
	CollectedAt      time.Time `json:"collected_at"`
}

func (c *ConfigurationCollector) Collect(ctx context.Context) (interface{}, error) {
	report := &ConfigurationReport{CollectedAt: time.Now().UTC()}

	if hasBinary("timedatectl") {
		if out, err := runCmdTimeout(ctx, 5*time.Second, "timedatectl", "show", "-p", "NTPSynchronized", "--value"); err == nil {
			synced := parseNTPSynchronized(string(out))
			report.TimeSynchronized = &synced
		}
	}

	report.SwapConfigured = parseSwapTotal(readProcFile("/proc/meminfo")) > 0

	return report, nil
}

// parseNTPSynchronized reads `timedatectl show -p NTPSynchronized --value`,
// which prints "yes" or "no".
func parseNTPSynchronized(out string) bool {
	return strings.EqualFold(strings.TrimSpace(out), "yes")
}

// parseSwapTotal returns SwapTotal (kB) from /proc/meminfo, 0 if absent.
func parseSwapTotal(meminfo string) int {
	for _, line := range strings.Split(meminfo, "\n") {
		if strings.HasPrefix(line, "SwapTotal:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				n := 0
				for _, ch := range f[1] {
					if ch < '0' || ch > '9' {
						break
					}
					n = n*10 + int(ch-'0')
				}
				return n
			}
		}
	}
	return 0
}
