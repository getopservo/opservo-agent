package collectors

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/getopservo/opservo-agent/buffer"
)

const (
	maxLinesPerSource = 200
	// maxTailBytes bounds how far back one read of a file goes (readNewLines).
	maxTailBytes  = 1 << 20
	maxMessageLen = 500
	maxLogsBytes  = 100 * 1024 // keep the logs array under 100KB
)

// LogEntry is one normalized log line shipped to the API.
type LogEntry struct {
	Source      string    `json:"source"` // nginx|apache|laravel|docker|pm2|systemd
	Level       string    `json:"level"`  // error|warning|info
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	ServiceName string    `json:"service_name,omitempty"`
}

// LogsCollector tails log files and queries log-producing commands, shipping
// only lines not seen in a previous heartbeat. File sources are deduplicated by
// a byte-offset cursor; command sources by content hash. Both live in the
// SQLite buffer. Every source is isolated with recover() so one bad source
// cannot crash the collector.
type LogsCollector struct {
	buf *buffer.Buffer
}

func NewLogsCollector(buf *buffer.Buffer) *LogsCollector { return &LogsCollector{buf: buf} }
func (c *LogsCollector) Name() string                    { return "logs" }

func (c *LogsCollector) Collect(ctx context.Context) (interface{}, error) {
	var entries []LogEntry

	// File-based sources — the byte-offset cursor handles cross-heartbeat dedup.
	entries = append(entries, c.safe("nginx", func() []LogEntry { return c.collectNginx() })...)
	entries = append(entries, c.safe("apache", func() []LogEntry { return c.collectApache() })...)
	entries = append(entries, c.safe("laravel", func() []LogEntry { return c.collectLaravel() })...)
	entries = append(entries, c.safe("pm2", func() []LogEntry { return c.collectPM2Logs(ctx) })...)
	redactEntries(entries)

	// Command-based sources — no file offset, so dedup by content hash.
	var cmd []LogEntry
	cmd = append(cmd, c.safe("docker", func() []LogEntry { return c.collectDockerLogs(ctx) })...)
	cmd = append(cmd, c.safe("systemd", func() []LogEntry { return c.collectJournald(ctx) })...)
	redactEntries(cmd) // before hashing, so the buffer never holds a secret either
	entries = append(entries, c.dedupCommand(cmd)...)

	entries = capBySize(entries)

	if c.buf != nil {
		_ = c.buf.PruneHashes(2 * time.Hour)
		// Drop cursors for paths not tailed in a week (log-rotated files) so the
		// file_cursors table doesn't grow forever on long-running hosts.
		_ = c.buf.PruneCursors(7 * 24 * time.Hour)
	}
	if entries == nil {
		entries = []LogEntry{}
	}
	return entries, nil
}

// redactEntries masks secrets in every message in place (see redact.go).
func redactEntries(entries []LogEntry) {
	for i := range entries {
		entries[i].Message = RedactSecrets(entries[i].Message)
	}
}

// safe runs a source and converts any panic into a logged warning.
func (c *LogsCollector) safe(source string, fn func() []LogEntry) (entries []LogEntry) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("log source panicked", "source", source, "panic", r)
			entries = nil
		}
	}()
	return fn()
}

// dedupCommand drops command-source entries whose content hash was shipped in a
// prior heartbeat, and records the new ones.
func (c *LogsCollector) dedupCommand(in []LogEntry) []LogEntry {
	if c.buf == nil {
		return in
	}
	var out []LogEntry
	var fresh []string
	for _, e := range in {
		h := entryHash(e)
		seen, err := c.buf.Seen(h)
		if err != nil {
			out = append(out, e) // on error, prefer delivering over dropping
			continue
		}
		if seen {
			continue
		}
		out = append(out, e)
		fresh = append(fresh, h)
	}
	if err := c.buf.MarkSeen(fresh); err != nil {
		slog.Warn("buffer mark seen failed", "error", err)
	}
	return out
}

// capBySize keeps the newest entries that fit within maxLogsBytes.
func capBySize(entries []LogEntry) []LogEntry {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Timestamp.After(entries[j].Timestamp) })
	total := 2 // for the [] wrapper
	for i, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		total += len(b) + 1
		if total > maxLogsBytes {
			return entries[:i]
		}
	}
	return entries
}

func entryHash(e LogEntry) string {
	sum := sha1.Sum([]byte(e.Source + "|" + e.ServiceName + "|" + e.Message))
	return hex.EncodeToString(sum[:])
}

// ── File reading ─────────────────────────────────────────────────────────────

// readNewLines returns lines appended to a file since the last heartbeat, using
// the buffer cursor. Handles rotation/truncation by restarting from offset 0.
func (c *LogsCollector) readNewLines(path string) []string {
	fi, err := os.Stat(path)
	if err != nil {
		return nil // missing file → skip gracefully
	}
	size := fi.Size()

	var offset, prevSize int64
	if c.buf != nil {
		offset, prevSize, _ = c.buf.Cursor(path)
	}
	if size < prevSize || offset > size {
		offset = 0 // rotated or truncated
	}
	// Never read more than a bounded window in one pass. With no cursor yet
	// (first heartbeat after install, or a rotated file) this used to walk a
	// multi-GB access log from byte 0 and hold every line in memory before
	// trimming to maxLinesPerSource. Only the newest lines ship anyway, so
	// start inside the last maxTailBytes and skip the partial line we land in.
	window := int64(maxTailBytes)
	if c.buf == nil {
		window = 64 * 1024 // no buffer: only tail recent bytes
	}
	skipPartial := false
	if size-offset > window {
		offset = size - window
		skipPartial = true
	}

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			offset = 0
			skipPartial = false
		}
	}

	var lines []string
	rd := bufio.NewReaderSize(f, 64*1024)
	complete := true
	if skipPartial {
		if _, err := rd.ReadString('\n'); err != nil {
			complete = false // no newline in the window: nothing complete to ship
		}
	}
	if complete {
		scanner := bufio.NewScanner(rd)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			if line := scanner.Text(); strings.TrimSpace(line) != "" {
				lines = append(lines, line)
			}
		}
	}
	if c.buf != nil {
		_ = c.buf.SetCursor(path, size, size)
	}
	if len(lines) > maxLinesPerSource {
		lines = lines[len(lines)-maxLinesPerSource:]
	}
	return lines
}

func fileMtime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Now()
}

// ── Source collectors ────────────────────────────────────────────────────────

func (c *LogsCollector) collectNginx() []LogEntry {
	var out []LogEntry
	// Default logs + any per-vhost logs (e.g. lotterylab-error.log).
	for _, path := range logFilesMatching("/var/log/nginx/error.log", "/var/log/nginx/*error*.log") {
		out = append(out, c.parseFile(path, "nginx", "nginx", parseNginxError)...)
	}
	for _, path := range logFilesMatching("/var/log/nginx/access.log", "/var/log/nginx/*access*.log") {
		out = append(out, c.parseFile(path, "nginx", "nginx", parseAccessLine)...)
	}
	return out
}

func (c *LogsCollector) collectApache() []LogEntry {
	var out []LogEntry
	// Debian (apache2) + RHEL (httpd), including per-vhost logs.
	for _, path := range logFilesMatching("/var/log/apache2/error.log", "/var/log/apache2/*error*.log", "/var/log/httpd/*error*.log") {
		out = append(out, c.parseFile(path, "apache", "apache", parseApacheError)...)
	}
	for _, path := range logFilesMatching("/var/log/apache2/access.log", "/var/log/apache2/*access*.log", "/var/log/httpd/*access*.log") {
		out = append(out, c.parseFile(path, "apache", "apache", parseAccessLine)...)
	}
	return out
}

func (c *LogsCollector) collectLaravel() []LogEntry {
	var out []LogEntry
	seen := map[string]bool{}
	// Match both the `single` channel (laravel.log) and the `daily` channel
	// (laravel-YYYY-MM-DD.log), plus apps nested one level deeper and Forge-style
	// /home/<user>/<site>. The byte-offset cursor dedups across heartbeats.
	for _, pat := range []string{
		"/var/www/*/storage/logs/*.log",
		"/var/www/*/*/storage/logs/*.log",
		"/home/*/*/storage/logs/*.log",
		"/srv/www/*/storage/logs/*.log",
	} {
		matches, _ := filepath.Glob(pat)
		for _, path := range matches {
			if seen[path] {
				continue
			}
			seen[path] = true
			out = append(out, c.parseFile(path, "laravel", laravelAppName(path), parseLaravelLine)...)
		}
	}
	return out
}

// logFilesMatching expands globs/paths into a de-duplicated list of existing
// files (filepath.Glob only returns paths that exist).
func logFilesMatching(patterns ...string) []string {
	seen := map[string]bool{}
	var files []string
	for _, pat := range patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		for _, f := range matches {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}
	return files
}

func (c *LogsCollector) collectPM2Logs(ctx context.Context) []LogEntry {
	var out []LogEntry
	for _, f := range pm2ErrorLogFiles(ctx) {
		for _, line := range c.readNewLines(f.Path) {
			out = append(out, LogEntry{
				Source:      "pm2",
				Level:       "error", // these are the error logs
				Message:     truncate(line),
				Timestamp:   parseLeadingTime(line, fileMtime(f.Path)),
				ServiceName: f.App,
			})
		}
	}
	return out
}

// parseFile reads new lines from a file, folds multi-line entries (stack
// traces) into their parent line, and maps each through parse.
func (c *LogsCollector) parseFile(path, source, service string, parse func(string, time.Time) (string, string)) []LogEntry {
	fallback := fileMtime(path)
	var out []LogEntry
	for _, line := range groupLines(c.readNewLines(path)) {
		level, msg := parse(line, fallback)
		out = append(out, LogEntry{
			Source:      source,
			Level:       level,
			Message:     truncate(msg),
			Timestamp:   parseLineTime(line, source, fallback),
			ServiceName: service,
		})
	}
	return out
}

func (c *LogsCollector) collectDockerLogs(ctx context.Context) []LogEntry {
	if !hasBinary("docker") {
		return nil
	}
	var entries []LogEntry
	for _, c := range listContainers(ctx) {
		name := c.Name
		// Capped: 200 lines of a container that logs 1 MB JSON lines would
		// otherwise be ~200 MB held in memory every minute.
		logs, err := runCmdTail(ctx, defaultCmdTimeout, maxDockerLogBytes, "docker", "logs", "--tail", "200", "--since", "1h", "--timestamps", name)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(logs)))
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		var lines []LogEntry
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ts, msg := splitDockerTimestamp(line)
			lines = append(lines, LogEntry{
				Source:      "docker",
				Level:       dockerLineLevel(msg),
				Message:     truncate(msg),
				Timestamp:   ts,
				ServiceName: name,
			})
		}
		if len(lines) > maxLinesPerSource {
			lines = lines[len(lines)-maxLinesPerSource:]
		}
		entries = append(entries, lines...)
	}
	return entries
}

// journaldEntry is the subset of `journalctl -o json` we read.
type journaldEntry struct {
	Message  string `json:"MESSAGE"`
	Priority string `json:"PRIORITY"`
	Unit     string `json:"_SYSTEMD_UNIT"`
	Realtime string `json:"__REALTIME_TIMESTAMP"`
}

func (c *LogsCollector) collectJournald(ctx context.Context) []LogEntry {
	if !hasBinary("journalctl") {
		return nil
	}
	// -p warning restricts to priority <= warning (i.e. warnings and errors only).
	out, err := runCmd(ctx, "journalctl", "-p", "warning", "-n", "200",
		"--since", "1 hour ago", "--no-pager", "-o", "json")
	if err != nil {
		return nil
	}
	var entries []LogEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var j journaldEntry
		if err := json.Unmarshal(scanner.Bytes(), &j); err != nil || j.Message == "" {
			continue
		}
		entries = append(entries, LogEntry{
			Source:      "systemd",
			Level:       priorityLevel(j.Priority),
			Message:     truncate(j.Message),
			Timestamp:   journalTime(j.Realtime),
			ServiceName: strings.TrimSuffix(j.Unit, ".service"),
		})
	}
	if len(entries) > maxLinesPerSource {
		entries = entries[len(entries)-maxLinesPerSource:]
	}
	return entries
}

// ── Multi-line grouping ──────────────────────────────────────────────────────

// entryStartRe matches the first line of a log entry: a leading timestamp in the
// formats used by Laravel ([2026-06-15 10:00:00]), nginx (2026/06/15 10:00:00),
// ISO (2026-06-15T10:00:00), Apache ([Mon Jun 15 ...]), and nginx/apache access
// logs (`1.2.3.4 - - [15/Jun/2026:10:00:00 +0000] "GET …`). Lines that do not
// match are continuations (stack frames, JSON, "#12 ...", "{main}"). Without
// the access-log form every access line after the first was folded into one
// "⏎"-joined entry, levelled by whichever status appeared first.
var entryStartRe = regexp.MustCompile(`^\[?\d{4}[-/]\d{2}[-/]\d{2}[ T]|^\[\w{3} \w{3} +\d|^\S+ \S+ \S+ \[\d{1,2}/\w{3}/\d{4}:`)

func isEntryStart(line string) bool {
	return entryStartRe.MatchString(strings.TrimLeft(line, " \t"))
}

// groupLines folds continuation lines (e.g. a Laravel/Java/Python stack trace)
// into the entry they belong to, so one exception becomes one log entry instead
// of dozens of fragments. The first line always starts an entry.
func groupLines(lines []string) []string {
	grouped := make([]string, 0, len(lines))
	for _, line := range lines {
		if len(grouped) > 0 && !isEntryStart(line) {
			last := len(grouped) - 1
			if len(grouped[last]) < maxMessageLen { // keep the merged message bounded
				grouped[last] = grouped[last] + " ⏎ " + strings.TrimSpace(line)
			}
			continue
		}
		grouped = append(grouped, line)
	}
	return grouped
}

// ── Parsing helpers ──────────────────────────────────────────────────────────

var (
	bracketLevelRe = regexp.MustCompile(`\[([a-zA-Z]+)\]`)
	apacheLevelRe  = regexp.MustCompile(`\[[a-z0-9_]+:([a-z]+)\]`)
	laravelLevelRe = regexp.MustCompile(`\]\s+[\w-]+\.([A-Z]+):`)
	accessStatusRe = regexp.MustCompile(`"\s(\d{3})\s`)
	nginxTimeRe    = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`)
	bracketTimeRe  = regexp.MustCompile(`\[([^\]]+)\]`)
)

func parseNginxError(line string, _ time.Time) (level, msg string) {
	level = "error"
	if m := bracketLevelRe.FindStringSubmatch(line); m != nil {
		level = normLevel(m[1])
	}
	return level, line
}

func parseApacheError(line string, _ time.Time) (level, msg string) {
	level = "error"
	if m := apacheLevelRe.FindStringSubmatch(line); m != nil {
		level = normLevel(m[1])
	}
	return level, line
}

func parseLaravelLine(line string, _ time.Time) (level, msg string) {
	level = "info"
	if m := laravelLevelRe.FindStringSubmatch(line); m != nil {
		level = normLevel(m[1])
	}
	return level, line
}

// parseAccessLine levels an HTTP access-log line by its status code.
func parseAccessLine(line string, _ time.Time) (level, msg string) {
	level = "info"
	if m := accessStatusRe.FindStringSubmatch(line); m != nil {
		switch m[1][0] {
		case '5':
			level = "error"
		case '4':
			level = "warning"
		}
	}
	return level, line
}

// Zone-less log timestamps (nginx error.log, apache error.log, Laravel,
// bare ISO-8601) are written in the server's LOCAL time zone. Parsing them
// as UTC (time.Parse's default) shifted every line by the UTC offset — on an
// IST box that put `last_seen` 5½ h in the future, so a "Resolve" watermark
// set right after a fix was wiped by an occurrence that had really happened
// BEFORE the fix, and the finding came straight back.
func parseLocalTime(layout, value string) (time.Time, error) {
	return time.ParseInLocation(layout, value, time.Local)
}

func parseLineTime(line, source string, fallback time.Time) time.Time {
	switch source {
	case "nginx":
		if m := nginxTimeRe.FindStringSubmatch(line); m != nil {
			if t, err := parseLocalTime("2006/01/02 15:04:05", m[1]); err == nil {
				return t
			}
		}
		if m := bracketTimeRe.FindStringSubmatch(line); m != nil {
			if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[1]); err == nil {
				return t
			}
		}
	case "apache":
		if m := bracketTimeRe.FindStringSubmatch(line); m != nil {
			if t, err := parseLocalTime("Mon Jan 02 15:04:05.000000 2006", m[1]); err == nil {
				return t
			}
			if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[1]); err == nil {
				return t
			}
		}
	case "laravel":
		if m := bracketTimeRe.FindStringSubmatch(line); m != nil {
			if t, err := parseLocalTime("2006-01-02 15:04:05", m[1]); err == nil {
				return t
			}
		}
	}
	return fallback
}

func parseLeadingTime(line string, fallback time.Time) time.Time {
	fields := strings.Fields(line)
	if len(fields) > 0 {
		head := strings.TrimSuffix(fields[0], ":")
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if t, err := time.Parse(layout, head); err == nil {
				return t
			}
		}
		if t, err := parseLocalTime("2006-01-02T15:04:05", head); err == nil {
			return t
		}
	}
	return fallback
}

func splitDockerTimestamp(line string) (time.Time, string) {
	space := strings.IndexByte(line, ' ')
	if space > 0 {
		if t, err := time.Parse(time.RFC3339Nano, line[:space]); err == nil {
			return t, strings.TrimSpace(line[space+1:])
		}
	}
	return time.Now(), line
}

func journalTime(realtime string) time.Time {
	if micros, err := strconv.ParseInt(realtime, 10, 64); err == nil && micros > 0 {
		return time.Unix(0, micros*1000).UTC()
	}
	return time.Now()
}

func priorityLevel(p string) string {
	n, err := strconv.Atoi(p)
	if err != nil {
		return "info"
	}
	switch {
	case n <= 3: // emerg..err
		return "error"
	case n == 4: // warning
		return "warning"
	default:
		return "info"
	}
}

func normLevel(s string) string {
	switch strings.ToLower(s) {
	case "emerg", "alert", "crit", "critical", "error", "err", "fatal":
		return "error"
	case "warn", "warning":
		return "warning"
	default:
		return "info"
	}
}

// dockerLineLevel classifies one container log line. Structured (JSON) lines
// are read by their level field; only unstructured lines fall back to keyword
// matching. Before this, every JSON line was keyword-matched as a whole, so
// pino's info-level `{"level":30,...,"req":{"url":"/api/v1/blog/errors"},
// "msg":"incoming request"}` counted as an error because the URL contained
// "error" — a critical "Recurring error in docker logs" on the staging box
// (15 Oct 2026). Any JSON logger trips the same way on a URL, user agent or
// field name containing error/fatal/panic/exception/warn.
func dockerLineLevel(msg string) string {
	if level, ok := jsonLineLevel(msg); ok {
		return level
	}
	return levelFromKeywords(msg)
}

// jsonLevelKeys are the field names JSON loggers use for the level, in the
// order we trust them: pino/bunyan/zerolog/logrus/structlog use "level",
// Google Cloud / Python logging use "severity", some use "lvl"/"loglevel".
var jsonLevelKeys = []string{"level", "severity", "lvl", "loglevel", "log.level"}

// jsonMessageKeys are the fields keyword matching may look at when a JSON
// line has no level field — never the whole object.
var jsonMessageKeys = []string{"msg", "message", "err", "error", "stack"}

// jsonLineLevel returns the level of a structured log line and true, or
// ("", false) when the line is not a JSON object.
func jsonLineLevel(line string) (string, bool) {
	if len(line) == 0 || line[0] != '{' {
		return "", false
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(line), &obj); err != nil || obj == nil {
		return "", false
	}
	for _, k := range jsonLevelKeys {
		v, ok := obj[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case float64:
			return numericLogLevel(t), true
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
				return numericLogLevel(float64(n)), true
			}
			if strings.TrimSpace(t) != "" {
				return normLevel(strings.TrimSpace(t)), true
			}
		}
	}
	// No level field: match keywords against the message-like fields only.
	var parts []string
	for _, k := range jsonMessageKeys {
		v, ok := obj[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			parts = append(parts, t)
		default:
			if b, err := json.Marshal(t); err == nil {
				parts = append(parts, string(b))
			}
		}
	}
	if len(parts) == 0 {
		return "info", true
	}
	return levelFromKeywords(strings.Join(parts, " ")), true
}

// numericLogLevel maps pino/bunyan numeric levels (10 trace, 20 debug,
// 30 info, 40 warn, 50 error, 60 fatal) and syslog-style 0–7 severities.
func numericLogLevel(n float64) string {
	switch {
	case n >= 50:
		return "error"
	case n >= 40:
		return "warning"
	case n >= 10:
		return "info"
	}
	// 0–7: syslog severity (0 emerg … 3 err, 4 warning, 5+ notice/info/debug).
	switch {
	case n <= 3:
		return "error"
	case n == 4:
		return "warning"
	default:
		return "info"
	}
}

func levelFromKeywords(msg string) string {
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, "error"), strings.Contains(l, "fatal"),
		strings.Contains(l, "panic"), strings.Contains(l, "exception"):
		return "error"
	case strings.Contains(l, "warn"):
		return "warning"
	default:
		return "info"
	}
}

func laravelAppName(path string) string {
	// /var/www/<app>/storage/logs/laravel.log -> <app>
	parts := strings.Split(path, string(os.PathSeparator))
	for i, p := range parts {
		if p == "www" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "laravel"
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxMessageLen {
		return s[:maxMessageLen]
	}
	return s
}
