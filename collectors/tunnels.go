package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	gopsnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// Cloudflare Tunnel routes: which public hostname a cloudflared tunnel sends
// to which local service. A site behind a tunnel has no nginx/apache vhost on
// the box, so without this Opservo cannot tell what serves it.
//
// Two kinds of tunnel:
//   - locally configured: ingress rules in a config.yml we can read;
//   - remotely managed (`cloudflared tunnel run --token …`): rules live in the
//     Cloudflare dashboard. cloudflared reports the config it is running on
//     its loopback metrics server (/config) and logs it as "Updated to new
//     configuration config=…" — we read those, never the token.

// tunnelRoute is one hostname → service ingress rule.
type tunnelRoute struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}

type ingressDoc struct {
	Ingress []tunnelRoute `json:"ingress"`
}

var tunnelConfigGlobs = []string{
	"/etc/cloudflared/config.yml", "/etc/cloudflared/config.yaml",
	"/usr/local/etc/cloudflared/config.yml", "/usr/local/etc/cloudflared/config.yaml",
	"/root/.cloudflared/config.yml", "/root/.cloudflared/config.yaml",
	"/home/*/.cloudflared/config.yml", "/home/*/.cloudflared/config.yaml",
}

var (
	tunnelCacheMu sync.Mutex
	tunnelCacheAt time.Time
	tunnelCache   map[string]string
)

// tunnelRoutes maps each tunnelled hostname to its service, from every source
// (cached 5 min: routes change rarely and this may hit a local HTTP endpoint).
func tunnelRoutes(ctx context.Context) map[string]string {
	tunnelCacheMu.Lock()
	defer tunnelCacheMu.Unlock()
	if tunnelCache != nil && time.Since(tunnelCacheAt) < 5*time.Minute {
		return tunnelCache
	}
	out := map[string]string{}
	add := func(routes []tunnelRoute) {
		for _, r := range routes {
			h := strings.TrimSpace(r.Hostname)
			if !isResolvableDomain(h) || r.Service == "" {
				continue // catch-all rule (http_status:404) has no hostname
			}
			if _, ok := out[h]; !ok {
				out[h] = cleanUpstream(RedactSecrets(r.Service))
			}
		}
	}
	for _, g := range tunnelConfigGlobs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			if data, err := os.ReadFile(f); err == nil {
				add(parseTunnelYAML(data))
			}
		}
	}
	if hasCloudflaredProcess(ctx) {
		for _, port := range cloudflaredMetricsPorts(ctx) {
			add(fetchTunnelConfig(ctx, port))
		}
		if len(out) == 0 {
			add(tunnelRoutesFromJournal(ctx))
		}
	}
	tunnelCache, tunnelCacheAt = out, time.Now()
	return out
}

// parseTunnelYAML reads the ingress list of a cloudflared config.yml. A
// small line parser instead of a YAML library (keeps ~260 KB out of the
// agent): cloudflared configs use block lists of "- key: value" maps.
func parseTunnelYAML(data []byte) []tunnelRoute {
	var out []tunnelRoute
	inIngress, itemIndent := false, -1
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inIngress = strings.HasPrefix(trimmed, "ingress:")
			itemIndent = -1
			continue
		}
		if !inIngress {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			if itemIndent < 0 {
				itemIndent = indent
			}
			if indent == itemIndent {
				out = append(out, tunnelRoute{})
				trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			}
		}
		if len(out) == 0 {
			continue
		}
		key, val, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(stripYAMLComment(val)), `"'`)
		switch strings.TrimSpace(key) {
		case "hostname":
			if indent <= itemIndent+2 {
				out[len(out)-1].Hostname = val
			}
		case "service":
			if indent <= itemIndent+2 {
				out[len(out)-1].Service = val
			}
		}
	}
	return out
}

func stripYAMLComment(v string) string {
	if i := strings.Index(v, " #"); i >= 0 {
		return v[:i]
	}
	return v
}

// parseTunnelConfigJSON reads cloudflared's running config as served by its
// metrics server ({"version":N,"config":{"ingress":[…]}}) or logged on update
// ({"ingress":[…]}). The config may itself be a JSON string.
func parseTunnelConfigJSON(data []byte) []tunnelRoute {
	var top struct {
		Ingress []tunnelRoute   `json:"ingress"`
		Config  json.RawMessage `json:"config"`
	}
	if json.Unmarshal(data, &top) != nil {
		return nil
	}
	if len(top.Ingress) > 0 {
		return top.Ingress
	}
	if len(top.Config) == 0 {
		return nil
	}
	var inner []byte = top.Config
	var asString string
	if json.Unmarshal(top.Config, &asString) == nil {
		inner = []byte(asString)
	}
	var doc ingressDoc
	if json.Unmarshal(inner, &doc) != nil {
		return nil
	}
	return doc.Ingress
}

func hasCloudflaredProcess(ctx context.Context) bool {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return false
	}
	for _, p := range procs {
		if n, err := p.NameWithContext(ctx); err == nil && n == "cloudflared" {
			return true
		}
	}
	return false
}

// cloudflaredMetricsPorts returns loopback TCP ports a cloudflared process listens on.
func cloudflaredMetricsPorts(ctx context.Context) []uint32 {
	conns, err := gopsnet.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return nil
	}
	names := map[int32]string{}
	var ports []uint32
	for _, c := range conns {
		if c.Status != "LISTEN" || c.Pid <= 0 {
			continue
		}
		if ip := c.Laddr.IP; ip != "127.0.0.1" && ip != "::1" && ip != "localhost" {
			continue
		}
		name, ok := names[c.Pid]
		if !ok {
			if p, err := process.NewProcessWithContext(ctx, c.Pid); err == nil {
				name, _ = p.NameWithContext(ctx)
			}
			names[c.Pid] = name
		}
		if name == "cloudflared" {
			ports = append(ports, c.Laddr.Port)
		}
	}
	return ports
}

var tunnelHTTP = &http.Client{Timeout: 2 * time.Second}

func fetchTunnelConfig(ctx context.Context, port uint32) []tunnelRoute {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/config", port), nil)
	if err != nil {
		return nil
	}
	resp, err := tunnelHTTP.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	return parseTunnelConfigJSON(body)
}

var tunnelLogConfigRe = regexp.MustCompile(`Updated to new configuration config="((?:[^"\\]|\\.)*)"`)

// tunnelRoutesFromJournal reads the newest "Updated to new configuration"
// line cloudflared logged (remote-managed tunnels log their ingress there).
func tunnelRoutesFromJournal(ctx context.Context) []tunnelRoute {
	if !hasBinary("journalctl") {
		return nil
	}
	out, err := runCmdTimeout(ctx, 5*time.Second, "journalctl", "-u", "cloudflared", "--no-pager", "-o", "cat", "-n", "5000")
	if err != nil {
		return nil
	}
	return parseTunnelLog(string(out))
}

func parseTunnelLog(log string) []tunnelRoute {
	ms := tunnelLogConfigRe.FindAllStringSubmatch(log, -1)
	if len(ms) == 0 {
		return nil
	}
	cfg, err := strconv.Unquote(`"` + ms[len(ms)-1][1] + `"`)
	if err != nil {
		return nil
	}
	return parseTunnelConfigJSON([]byte(cfg))
}
