package collectors

import (
	"bytes"
	"context"
	"os"
)

// ScheduledInfo is the raw view of systemd timers and cron jobs, collected each
// heartbeat so the dashboard shows them instantly without running a live command.
type ScheduledInfo struct {
	Timers string `json:"timers"`
	Cron   string `json:"cron"`
}

type ScheduledCollector struct{}

func NewScheduledCollector() *ScheduledCollector { return &ScheduledCollector{} }
func (s *ScheduledCollector) Name() string       { return "scheduled" }

func (s *ScheduledCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &ScheduledInfo{}

	if hasBinary("systemctl") {
		if out, err := runCmd(ctx, "systemctl", "list-timers", "--all", "--no-pager"); err == nil {
			info.Timers = capText(string(out), 16000)
		}
	}

	var cron bytes.Buffer
	appendFile(&cron, "# /etc/crontab", "/etc/crontab")
	if entries, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range entries {
			appendFile(&cron, "# /etc/cron.d/"+e.Name(), "/etc/cron.d/"+e.Name())
		}
	}
	// Per-user crontabs (Debian/Ubuntu location). The agent runs privileged so
	// these are readable.
	if entries, err := os.ReadDir("/var/spool/cron/crontabs"); err == nil {
		for _, e := range entries {
			appendFile(&cron, "# user: "+e.Name(), "/var/spool/cron/crontabs/"+e.Name())
		}
	}
	info.Cron = capText(cron.String(), 16000)
	return info, nil
}

// appendFile writes a header + a file's contents to buf, skipping unreadable files.
func appendFile(buf *bytes.Buffer, header, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	buf.WriteString(header)
	buf.WriteByte('\n')
	buf.Write(data)
	buf.WriteByte('\n')
}

// capText trims text to a maximum length so the snapshot stays small.
func capText(s string, max int) string {
	if len(s) > max {
		return s[:max] + "\n…[truncated]"
	}
	return s
}
