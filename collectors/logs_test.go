package collectors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getopservo/opservo-agent/buffer"
)

func TestNormLevel(t *testing.T) {
	cases := map[string]string{
		"error": "error", "ERR": "error", "Crit": "error", "emerg": "error", "fatal": "error",
		"warn": "warning", "WARNING": "warning",
		"notice": "info", "info": "info", "debug": "info", "": "info",
	}
	for in, want := range cases {
		if got := normLevel(in); got != want {
			t.Errorf("normLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseAccessLine(t *testing.T) {
	cases := []struct {
		line  string
		level string
	}{
		{`1.2.3.4 - - [02/Jan/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 12`, "info"},
		{`1.2.3.4 - - [02/Jan/2024:15:04:05 +0000] "GET /x HTTP/1.1" 404 0`, "warning"},
		{`1.2.3.4 - - [02/Jan/2024:15:04:05 +0000] "POST /y HTTP/1.1" 500 0`, "error"},
	}
	for _, tc := range cases {
		if got, _ := parseAccessLine(tc.line, time.Now()); got != tc.level {
			t.Errorf("parseAccessLine status level = %q, want %q\n  %s", got, tc.level, tc.line)
		}
	}
}

func TestParseLaravelLine(t *testing.T) {
	level, _ := parseLaravelLine(`[2024-01-02 15:04:05] production.ERROR: Something broke`, time.Now())
	if level != "error" {
		t.Errorf("laravel level = %q, want error", level)
	}
	ts := parseLineTime(`[2024-01-02 15:04:05] production.ERROR: x`, "laravel", time.Unix(0, 0))
	if want := time.Date(2024, 1, 2, 15, 4, 5, 0, time.Local); !ts.Equal(want) {
		t.Errorf("laravel timestamp = %v, want local %v", ts, want)
	}
}

// Zone-less timestamps must be read in the server's local zone, not UTC:
// with TZ=Asia/Kolkata "15:04:05" is 09:34:05Z, and the result must never
// land in the future relative to the machine that wrote the line.
func TestParseLineTime_ZonelessIsLocal(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	prev := time.Local
	time.Local = loc
	t.Cleanup(func() { time.Local = prev })

	want := time.Date(2024, 1, 2, 9, 34, 5, 0, time.UTC)
	cases := []struct{ line, source string }{
		{`2024/01/02 15:04:05 [error] 1#0: *1 upstream prematurely closed`, "nginx"},
		{`[Tue Jan 02 15:04:05.000000 2024] [core:error] [pid 1] x`, "apache"},
		{`[2024-01-02 15:04:05] production.ERROR: x`, "laravel"},
	}
	for _, c := range cases {
		if got := parseLineTime(c.line, c.source, time.Unix(0, 0)); !got.Equal(want) {
			t.Errorf("%s: got %v, want %v", c.source, got.UTC(), want)
		}
	}
	if got := parseLeadingTime(`2024-01-02T15:04:05 something`, time.Unix(0, 0)); !got.Equal(want) {
		t.Errorf("leading ISO: got %v, want %v", got.UTC(), want)
	}
	// A timestamp that carries its own zone is never re-interpreted.
	zoned := parseLineTime(`1.2.3.4 - - [02/Jan/2024:15:04:05 +0000] "GET / HTTP/1.1" 200 1`, "nginx", time.Unix(0, 0))
	if !zoned.Equal(time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)) {
		t.Errorf("zoned access-log time re-interpreted: %v", zoned)
	}
}

func TestParseNginxError(t *testing.T) {
	level, _ := parseNginxError(`2024/01/02 15:04:05 [warn] 123#0: *1 something`, time.Now())
	if level != "warning" {
		t.Errorf("nginx level = %q, want warning", level)
	}
	ts := parseLineTime(`2024/01/02 15:04:05 [warn] 123#0: x`, "nginx", time.Unix(0, 0))
	if ts.Year() != 2024 {
		t.Errorf("nginx timestamp parse failed: %v", ts)
	}
}

func TestPriorityLevel(t *testing.T) {
	cases := map[string]string{"0": "error", "3": "error", "4": "warning", "6": "info", "x": "info"}
	for in, want := range cases {
		if got := priorityLevel(in); got != want {
			t.Errorf("priorityLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitDockerTimestamp(t *testing.T) {
	ts, msg := splitDockerTimestamp("2024-01-02T15:04:05.123456789Z something happened")
	if ts.Year() != 2024 {
		t.Errorf("docker ts parse failed: %v", ts)
	}
	if msg != "something happened" {
		t.Errorf("docker msg = %q", msg)
	}
}

func TestTruncate(t *testing.T) {
	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	if got := truncate(string(long)); len(got) != maxMessageLen {
		t.Errorf("truncate len = %d, want %d", len(got), maxMessageLen)
	}
}

func TestCapBySize(t *testing.T) {
	// Build entries far exceeding 100KB; ensure result fits and keeps newest.
	base := time.Now()
	big := make([]byte, 1000)
	for i := range big {
		big[i] = 'x'
	}
	var entries []LogEntry
	for i := 0; i < 500; i++ {
		entries = append(entries, LogEntry{
			Source:    "test",
			Level:     "info",
			Message:   string(big),
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
	}
	capped := capBySize(entries)
	if len(capped) >= len(entries) {
		t.Errorf("expected truncation, got %d of %d", len(capped), len(entries))
	}
	// newest entry (largest timestamp) must be retained
	if !capped[0].Timestamp.Equal(base.Add(499 * time.Second)) {
		t.Errorf("expected newest entry first, got %v", capped[0].Timestamp)
	}
}

func TestGroupLines_FoldsLaravelStackTrace(t *testing.T) {
	lines := []string{
		`[2026-06-15 10:00:00] production.ERROR: Boom {"exception":"[object] (Exception(code: 0): Boom`,
		`#0 /var/www/app/artisan(16): Illuminate\Foundation\run()`,
		`#1 {main}`,
		`[stacktrace]`,
		`[2026-06-15 10:05:00] production.INFO: Recovered`,
		`2026/06/15 10:06:00 [error] nginx upstream timed out`,
	}
	got := groupLines(lines)
	if len(got) != 3 {
		t.Fatalf("expected 3 grouped entries, got %d: %#v", len(got), got)
	}
	if !strings.Contains(got[0], "Boom") || !strings.Contains(got[0], "#0") || !strings.Contains(got[0], "{main}") {
		t.Errorf("first entry should fold the stack trace: %q", got[0])
	}
	if !strings.Contains(got[1], "Recovered") {
		t.Errorf("second entry wrong: %q", got[1])
	}
	if !strings.Contains(got[2], "nginx upstream") {
		t.Errorf("nginx line should start its own entry: %q", got[2])
	}
}

func TestGroupLines_KeepsAccessLinesSeparate(t *testing.T) {
	lines := []string{
		`192.0.2.10 - - [15/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "probe/1.0"`,
		`192.0.2.11 - - [15/Jun/2026:10:00:01 +0000] "GET /api HTTP/1.1" 502 157 "-" "curl/8.0"`,
		`192.0.2.12 - - [15/Jun/2026:10:00:02 +0000] "POST /x HTTP/1.1" 404 0 "-" "-"`,
	}
	got := groupLines(lines)
	if len(got) != 3 {
		t.Fatalf("each access line is its own entry, got %d: %#v", len(got), got)
	}
	if lvl, _ := parseAccessLine(got[0], time.Time{}); lvl != "info" {
		t.Errorf("a 200 line must not inherit a later 5xx: %q", lvl)
	}
	if lvl, _ := parseAccessLine(got[1], time.Time{}); lvl != "error" {
		t.Errorf("502 should be error, got %q", lvl)
	}
}

func TestIsEntryStart(t *testing.T) {
	starts := []string{
		`[2026-06-15 10:00:00] production.ERROR: x`,
		`2026/06/15 10:00:00 [error] x`,
		`2026-06-15T10:00:00Z something`,
		`[Mon Jun 15 10:00:00 2026] [error] x`,
		`192.0.2.10 - - [15/Jun/2026:10:00:00 +0000] "GET / HTTP/1.1" 502 157 "-" "curl/8.0"`,
		`2001:db8::1 - alice [05/Jun/2026:10:00:00 +0530] "POST /api HTTP/2.0" 500 0 "-" "-"`,
	}
	conts := []string{`#0 /var/www/x.php(1): y()`, `{main}`, `[stacktrace]`, `    at Foo.bar()`, `"}`}
	for _, s := range starts {
		if !isEntryStart(s) {
			t.Errorf("expected entry start: %q", s)
		}
	}
	for _, s := range conts {
		if isEntryStart(s) {
			t.Errorf("expected continuation: %q", s)
		}
	}
}

func TestReadNewLines_FirstTailIsBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// ~3 MB of numbered lines, well past maxTailBytes.
	var n int
	for size := int64(0); size < 3*maxTailBytes; n++ {
		line := fmt.Sprintf("line-%08d %s\n", n, strings.Repeat("x", 80))
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
		size += int64(len(line))
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)

	buf, err := buffer.Open(filepath.Join(dir, "buf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()
	c := NewLogsCollector(buf)

	lines := c.readNewLines(path)
	if len(lines) != maxLinesPerSource {
		t.Fatalf("got %d lines, want %d", len(lines), maxLinesPerSource)
	}
	// Every shipped line is complete (we skipped the partial one we landed
	// in) and they are the newest ones.
	for _, l := range lines {
		if !strings.HasPrefix(l, "line-") || len(l) != len("line-00000000 ")+80 {
			t.Fatalf("partial or corrupt line shipped: %q", l)
		}
	}
	if want := fmt.Sprintf("line-%08d", n-1); !strings.HasPrefix(lines[len(lines)-1], want) {
		t.Fatalf("last line = %q, want prefix %q", lines[len(lines)-1], want)
	}
	// Cursor now at EOF: a second read ships nothing new.
	if off, size, _ := buf.Cursor(path); off != fi.Size() || size != fi.Size() {
		t.Fatalf("cursor = (%d,%d), want (%d,%d)", off, size, fi.Size(), fi.Size())
	}
	if again := c.readNewLines(path); len(again) != 0 {
		t.Fatalf("second read shipped %d lines", len(again))
	}
	// Append a line: only it ships.
	af, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	af.WriteString("line-appended tail\n")
	af.Close()
	if got := c.readNewLines(path); len(got) != 1 || got[0] != "line-appended tail" {
		t.Fatalf("after append got %v", got)
	}

	// No buffer: the 64 KB window applies and lines are still complete.
	nb := NewLogsCollector(nil)
	got := nb.readNewLines(path)
	if len(got) == 0 || len(got) > maxLinesPerSource {
		t.Fatalf("no-buffer read returned %d lines", len(got))
	}
	if !strings.HasPrefix(got[0], "line-") {
		t.Fatalf("no-buffer first line partial: %q", got[0])
	}
}
