package collectors

import (
	"bytes"
	"context"
	"os"
	"strings"
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
			info.Timers = capText(redactLines(string(out)), 16000)
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
	// Crontabs routinely carry `mysqldump -pSECRET`, `AWS_SECRET_ACCESS_KEY=…`
	// and curl tokens inline; they are shipped raw text, so mask every line
	// first (RedactSecrets is per-line: its generic rules stop at whitespace).
	info.Cron = capText(redactLines(cron.String()), 16000)
	return info, nil
}

// redactLines applies RedactSecrets to each line of a multi-line text.
func redactLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = RedactSecrets(l)
	}
	return strings.Join(lines, "\n")
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
