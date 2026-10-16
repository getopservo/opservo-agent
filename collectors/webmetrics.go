package collectors

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// WebInfo is a rolling-window summary of HTTP traffic parsed from nginx/apache
// access logs — request rate + status-code breakdown. App-level observability
// that needs no credentials (the agent already reads these logs). Aggregated
// across all detected access logs over the last WindowSeconds.
type WebInfo struct {
	Available       bool    `json:"available"`
	Sources         int     `json:"sources"`        // access-log files counted
	WindowSeconds   int     `json:"window_seconds"` // the rolling window
	Requests        int     `json:"requests"`       // total in the window
	ReqPerMin       float64 `json:"req_per_min"`    // requests/minute
	Status2xx       int     `json:"status_2xx"`
	Status3xx       int     `json:"status_3xx"`
	Status4xx       int     `json:"status_4xx"`
	Status5xx       int     `json:"status_5xx"`
	ErrorRate       float64 `json:"error_rate"`        // (4xx+5xx)/total %
	ServerErrorRate float64 `json:"server_error_rate"` // 5xx/total %
	BytesSent       int64   `json:"bytes_sent"`
}

type WebStats struct {
	Requests, S2xx, S3xx, S4xx, S5xx int
	Bytes                            int64
}

type WebMetricsCollector struct{}

func NewWebMetricsCollector() *WebMetricsCollector { return &WebMetricsCollector{} }
func (w *WebMetricsCollector) Name() string        { return "web" }

const webWindowSeconds = 300 // 5-minute rolling view
const webTailBytes = 512 * 1024

// `[28/Jun/2026:12:00:01 +0000] "GET /x HTTP/1.1" 200 1234` — the time + status +
// bytes triple is stable across nginx/apache combined & vhost_combined formats.
var accessRe = regexp.MustCompile(`\[([^\]]+)\]\s+"[^"]*"\s+(\d{3})\s+(\d+|-)`)

// Container name/image patterns that likely serve HTTP access logs to stdout.
var webContainerRe = regexp.MustCompile(`(?i)nginx|apache|httpd|openresty|caddy`)

const accessTimeLayout = "02/Jan/2006:15:04:05 -0700"

// parseAccessWindow tallies access-log lines whose timestamp is within the last
// windowSec of `now`. Pure + unit-tested.
func parseAccessWindow(content string, now time.Time, windowSec int) WebStats {
	var s WebStats
	cutoff := now.Add(-time.Duration(windowSec) * time.Second)
	for _, line := range strings.Split(content, "\n") {
		m := accessRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		t, err := time.Parse(accessTimeLayout, m[1])
		if err != nil || t.Before(cutoff) || t.After(now.Add(2*time.Minute)) {
			continue
		}
		code, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		s.Requests++
		switch code / 100 {
		case 2:
			s.S2xx++
		case 3:
			s.S3xx++
		case 4:
			s.S4xx++
		case 5:
			s.S5xx++
		}
		if b, err := strconv.ParseInt(m[3], 10, 64); err == nil {
			s.Bytes += b
		}
	}
	return s
}

func (w *WebMetricsCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &WebInfo{WindowSeconds: webWindowSeconds}
	now := time.Now()

	seen := map[string]bool{}
	patterns := []string{
		"/var/log/nginx/*access*.log",
		"/var/log/apache2/*access*.log",
		"/var/log/httpd/*access*.log",
	}
	for _, p := range patterns {
		matches, _ := filepath.Glob(p)
		for _, path := range matches {
			if seen[path] || strings.HasSuffix(path, ".gz") {
				continue
			}
			seen[path] = true
			content := tailFile(path, webTailBytes)
			if content == "" {
				continue
			}
			info.Available = true
			info.Sources++
			s := parseAccessWindow(content, now, webWindowSeconds)
			info.Requests += s.Requests
			info.Status2xx += s.S2xx
			info.Status3xx += s.S3xx
			info.Status4xx += s.S4xx
			info.Status5xx += s.S5xx
			info.BytesSent += s.Bytes
		}
	}

	// Containerized nginx/apache log access lines to the container's stdout, so
	// they never appear under host /var/log. Read them via `docker logs`.
	if hasBinary("docker") {
		for _, c := range listContainers(ctx) {
			name, image := c.Name, c.Image
			if !webContainerRe.MatchString(name) && !webContainerRe.MatchString(image) {
				continue
			}
			logs, err := runCmdTail(ctx, 6*time.Second, maxWebLogBytes, "docker", "logs", "--since", "6m", "--tail", "8000", name)
			if err != nil || len(logs) == 0 {
				continue
			}
			s := parseAccessWindow(string(logs), now, webWindowSeconds)
			if s.Requests == 0 {
				continue // a web-ish container with no parseable access logs (e.g. proxies)
			}
			info.Available = true
			info.Sources++
			info.Requests += s.Requests
			info.Status2xx += s.S2xx
			info.Status3xx += s.S3xx
			info.Status4xx += s.S4xx
			info.Status5xx += s.S5xx
			info.BytesSent += s.Bytes
		}
	}

	if info.Requests > 0 {
		info.ReqPerMin = float64(info.Requests) / (float64(webWindowSeconds) / 60.0)
		info.ErrorRate = float64(info.Status4xx+info.Status5xx) / float64(info.Requests) * 100
		info.ServerErrorRate = float64(info.Status5xx) / float64(info.Requests) * 100
	}
	return info, nil
}

// tailFile returns the last up-to maxBytes of a file as a string (best-effort).
func tailFile(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	start := int64(0)
	if fi.Size() > maxBytes {
		start = fi.Size() - maxBytes
	}
	if _, err := f.Seek(start, 0); err != nil {
		return ""
	}
	buf := make([]byte, fi.Size()-start)
	n, _ := f.Read(buf)
	return string(buf[:n])
}
