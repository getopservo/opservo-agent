package collectors

import (
	"context"
	"strconv"
	"strings"
)

// ContainerStat is one container's live resource usage (from `docker stats`).
type ContainerStat struct {
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	MemBytes   int64   `json:"mem_bytes"`    // memory in use
	MemPercent float64 `json:"mem_percent"`
	NetRxBytes int64   `json:"net_rx_bytes"` // cumulative
	NetTxBytes int64   `json:"net_tx_bytes"`
}

// ContainersInfo: per-container resource usage. App/container-level observability
// that needs no credentials (just Docker access, which the agent already has).
type ContainersInfo struct {
	Available  bool            `json:"available"`
	Containers []ContainerStat `json:"containers"`
}

type ContainersCollector struct{}

func NewContainersCollector() *ContainersCollector { return &ContainersCollector{} }
func (c *ContainersCollector) Name() string        { return "containers" }

func (c *ContainersCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &ContainersInfo{Containers: []ContainerStat{}}
	if !hasBinary("docker") {
		return info, nil
	}
	// --no-stream takes one sample and exits; bound it so a hung dockerd can't
	// stall the heartbeat. Shared with the services collector so this runs once
	// per cycle instead of twice.
	out, err := sharedDockerStats(ctx)
	if err != nil {
		return info, nil // docker present but not usable (no daemon / perms) — skip quietly
	}
	info.Available = true
	info.Containers = parseDockerStats(string(out))
	return info, nil
}

// parseDockerStats parses `docker stats --format` tab-separated output. Pure +
// unit-tested. Handles binary (MiB/GiB) and decimal (MB/GB) size suffixes.
func parseDockerStats(out string) []ContainerStat {
	var rows []ContainerStat
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 5 || f[0] == "" {
			continue
		}
		rx, tx := splitSlashSizes(f[4])
		used, _ := splitSlashSizes(f[2]) // "used / limit"
		rows = append(rows, ContainerStat{
			Name:       strings.TrimSpace(f[0]),
			CPUPercent: parsePercent(f[1]),
			MemBytes:   used,
			MemPercent: parsePercent(f[3]),
			NetRxBytes: rx,
			NetTxBytes: tx,
		})
	}
	return rows
}

func parsePercent(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%")), 64)
	return v
}

// splitSlashSizes parses "1.2GB / 800MB" -> (left bytes, right bytes).
func splitSlashSizes(s string) (int64, int64) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return parseDockerSize(s), 0
	}
	return parseDockerSize(parts[0]), parseDockerSize(parts[1])
}

// parseDockerSize parses "550.6MiB", "1.2GB", "0B", "4kB" -> bytes.
func parseDockerSize(s string) int64 {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	if i == 0 {
		return 0
	}
	num, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0
	}
	unit := strings.TrimSpace(s[i:])
	base := 1000.0
	if strings.Contains(unit, "i") { // KiB/MiB/GiB are binary
		base = 1024.0
	}
	mult := 1.0
	switch {
	case strings.HasPrefix(unit, "k"), strings.HasPrefix(unit, "K"):
		mult = base
	case strings.HasPrefix(unit, "M"):
		mult = base * base
	case strings.HasPrefix(unit, "G"):
		mult = base * base * base
	case strings.HasPrefix(unit, "T"):
		mult = base * base * base * base
	}
	return int64(num * mult)
}
