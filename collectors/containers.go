package collectors

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// ContainerStat is one container's live resource usage (from `docker stats`).
type ContainerStat struct {
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	MemBytes   int64   `json:"mem_bytes"` // memory in use
	MemPercent float64 `json:"mem_percent"`
	NetRxBytes int64   `json:"net_rx_bytes"` // cumulative
	NetTxBytes int64   `json:"net_tx_bytes"`

	// From `docker ps` (agents from Oct 2026): what the container is and how
	// it is reached, so the dashboard can say which container serves a site.
	Image   string          `json:"image,omitempty"`
	Project string          `json:"project,omitempty"` // docker compose project
	Status  string          `json:"status,omitempty"`  // e.g. "Up 4 weeks", "Restarting (1) 12 seconds ago"
	Ports   []PublishedPort `json:"ports,omitempty"`   // host ports published to the container
	// Owner: the login user whose ROOTLESS daemon runs the container; empty
	// for the system daemon (rootless.go).
	Owner string `json:"owner,omitempty"`
}

// PublishedPort is one host port Docker forwards into a container.
type PublishedPort struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
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
	if out, err := sharedDockerStats(ctx); err == nil {
		info.Available = true
		info.Containers = parseDockerStats(string(out))
		if ps, err := cachedCmd(ctx, 30*time.Second, 8*time.Second, "docker", "ps", "--no-trunc",
			"--format", containerPSFormat); err == nil {
			mergeDockerPS(info.Containers, string(ps))
		}
	}
	// docker present but not usable as root (no system daemon / perms) is not
	// an error: the host may only run rootless daemons.
	for _, d := range sharedRootlessDaemons(ctx) {
		out, err := d.stats(ctx)
		if err != nil {
			continue
		}
		rows := parseDockerStats(string(out))
		if ps, err := d.run(ctx, 8*time.Second, "ps", "--no-trunc", "--format", containerPSFormat); err == nil {
			mergeDockerPS(rows, string(ps))
		}
		for i := range rows {
			rows[i].Owner = d.User
		}
		info.Available = true
		info.Containers = append(info.Containers, rows...)
	}
	return info, nil
}

// containerPSFormat is the `docker ps` row mergeDockerPS parses.
const containerPSFormat = `{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project"}}\t{{.Status}}\t{{.Ports}}`

// mergeDockerPS adds image / compose project / status / published ports from
// `docker ps` rows (Name\tImage\tProject\tStatus\tPorts) onto the stats rows.
// Pure + unit-tested.
func mergeDockerPS(stats []ContainerStat, out string) {
	byName := map[string]*ContainerStat{}
	for i := range stats {
		byName[stats[i].Name] = &stats[i]
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		c := byName[strings.TrimSpace(f[0])]
		if c == nil {
			continue
		}
		c.Image = RedactSecrets(strings.TrimSpace(f[1])) // registry URLs can carry user:pass@
		c.Project = strings.TrimSpace(f[2])
		c.Status = strings.TrimSpace(f[3])
		c.Ports = parseDockerPorts(f[4])
	}
}

// parseDockerPorts parses the Ports column of `docker ps`, e.g.
// "0.0.0.0:8080->80/tcp, :::8080->80/tcp, 5432/tcp", keeping only ports
// published on the host (one entry per host port + protocol).
func parseDockerPorts(s string) []PublishedPort {
	var out []PublishedPort
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		arrow := strings.Index(part, "->")
		if arrow < 0 {
			continue // exposed but not published
		}
		host, target := part[:arrow], part[arrow+2:]
		colon := strings.LastIndex(host, ":")
		if colon < 0 {
			continue
		}
		hostIP, hostPortS := host[:colon], host[colon+1:]
		proto := "tcp"
		if slash := strings.Index(target, "/"); slash >= 0 {
			proto = target[slash+1:]
			target = target[:slash]
		}
		hostPort, err1 := strconv.Atoi(strings.SplitN(hostPortS, "-", 2)[0])
		ctrPort, err2 := strconv.Atoi(strings.SplitN(target, "-", 2)[0])
		if err1 != nil || err2 != nil {
			continue
		}
		key := hostPortS + "/" + proto
		if seen[key] {
			continue // same port on IPv4 and IPv6
		}
		seen[key] = true
		if hostIP == "::" || hostIP == "[::]" {
			hostIP = "0.0.0.0"
		}
		out = append(out, PublishedPort{HostIP: hostIP, HostPort: hostPort, ContainerPort: ctrPort, Protocol: proto})
	}
	return out
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
