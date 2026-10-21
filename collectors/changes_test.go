package collectors

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseDpkgLog(t *testing.T) {
	lines := []string{
		"2026-10-18 10:00:00 startup archives unpack",
		"2026-10-18 10:00:01 upgrade nginx:amd64 1.18.0-6ubuntu14.4 1.18.0-6ubuntu14.5",
		"2026-10-18 10:00:02 status half-configured nginx:amd64 1.18.0-6ubuntu14.5",
		"2026-10-18 10:00:05 install htop:amd64 <none> 3.0.5-7build2",
		"2026-10-18 10:00:09 remove telnet:amd64 0.17-44build1 <none>",
		"2026-10-18 10:00:10 purge telnet:amd64 <none> 0.17-44build1",
		"garbage line",
	}
	got := parseDpkgLog(lines, time.UTC)
	if len(got) != 4 {
		t.Fatalf("want 4 events, got %d: %+v", len(got), got)
	}
	up := got[0]
	if up.Action != "upgrade" || up.Package != "nginx" || up.From != "1.18.0-6ubuntu14.4" || up.To != "1.18.0-6ubuntu14.5" || up.At != "2026-10-18T10:00:01Z" {
		t.Errorf("upgrade parsed wrong: %+v", up)
	}
	if in := got[1]; in.Action != "install" || in.Package != "htop" || in.From != "" || in.To != "3.0.5-7build2" {
		t.Errorf("install parsed wrong: %+v", in)
	}
	if rm := got[2]; rm.Action != "remove" || rm.Package != "telnet" || rm.From != "0.17-44build1" || rm.To != "" {
		t.Errorf("remove parsed wrong: %+v", rm)
	}
	if pg := got[3]; pg.Action != "remove" || pg.From != "0.17-44build1" || pg.To != "" {
		t.Errorf("purge should read as remove with the version in From: %+v", pg)
	}
}

func TestParseDpkgLogLocalTime(t *testing.T) {
	loc := time.FixedZone("IST", 5*3600+1800)
	got := parseDpkgLog([]string{"2026-10-18 15:30:00 install x:amd64 <none> 1"}, loc)
	if len(got) != 1 || got[0].At != "2026-10-18T10:00:00Z" {
		t.Fatalf("local time not converted to UTC: %+v", got)
	}
}

func TestParseDnfRpmLog(t *testing.T) {
	lines := []string{
		"2026-10-18T10:00:00+0000 SUBDEBUG Upgrade: nginx-1:1.20.1-13.el9.x86_64",
		"2026-10-18T10:00:00+0000 SUBDEBUG Upgraded: nginx-1:1.20.1-14.el9.x86_64",
		"2026-10-18T10:00:01+0000 SUBDEBUG Installed: htop-3.2.2-1.el9.x86_64",
		"2026-10-18T10:00:02+0000 SUBDEBUG Erase: telnet-0.17-85.el9.x86_64",
		"2026-10-18T10:00:03+0000 INFO --- logging initialized ---",
	}
	got := parseDnfRpmLog(lines)
	if len(got) != 3 {
		t.Fatalf("want 3 events, got %d: %+v", len(got), got)
	}
	if got[0].Action != "upgrade" || got[0].Package != "nginx" || got[0].To != "1:1.20.1-14.el9" || got[0].At != "2026-10-18T10:00:00Z" {
		t.Errorf("upgraded parsed wrong: %+v", got[0])
	}
	if got[1].Action != "install" || got[1].Package != "htop" || got[1].To != "3.2.2-1.el9" {
		t.Errorf("installed parsed wrong: %+v", got[1])
	}
	if got[2].Action != "remove" || got[2].Package != "telnet" || got[2].From != "0.17-85.el9" {
		t.Errorf("erase parsed wrong: %+v", got[2])
	}
}

func TestSplitNEVRA(t *testing.T) {
	cases := map[string][2]string{
		"nginx-1:1.20.1-14.el9.x86_64":      {"nginx", "1:1.20.1-14.el9"},
		"python3-libs-3.9.18-3.el9.x86_64":  {"python3-libs", "3.9.18-3.el9"},
		"htop-3.2.2-1.el9.x86_64":           {"htop", "3.2.2-1.el9"},
		"kernel-core-5.14.0-427.el9.x86_64": {"kernel-core", "5.14.0-427.el9"},
	}
	for in, want := range cases {
		n, v := splitNEVRA(in)
		if n != want[0] || v != want[1] {
			t.Errorf("splitNEVRA(%q) = %q,%q want %q,%q", in, n, v, want[0], want[1])
		}
	}
}

func TestFilterRecentOnFirstRead(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	events := []PackageEvent{
		{Action: "install", Package: "old", At: now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)},
		{Action: "install", Package: "new", At: now.Add(-2 * time.Hour).Format(time.RFC3339)},
	}
	if got := filterRecent(events, now, false); len(got) != 2 {
		t.Fatalf("with a cursor every event ships; got %d", len(got))
	}
	got := filterRecent(append([]PackageEvent{}, events...), now, true)
	if len(got) != 1 || got[0].Package != "new" {
		t.Fatalf("first read should keep only the last week: %+v", got)
	}
}

func TestRecentConfigFiles(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	write := func(rel string, age time.Duration) string {
		p := filepath.Join(dir, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		mt := now.Add(-age)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fresh := write("nginx/sites-available/app.conf", time.Hour)
	write("nginx/nginx.conf", 10*24*time.Hour)            // too old
	write("nginx/sites-available/app.conf~", time.Minute) // editor backup → skipped
	write("nginx/a/b/c/d/deep.conf", time.Minute)         // beyond depth 3 → skipped
	_ = os.MkdirAll(filepath.Join(dir, "nginx/sites-enabled"), 0o755)
	link := filepath.Join(dir, "nginx/sites-enabled/app.conf")
	if err := os.Symlink(fresh, link); err != nil {
		t.Fatal(err)
	}
	single := write("hosts", 2*time.Hour)

	roots := []struct{ path, area string }{
		{filepath.Join(dir, "nginx"), "nginx"},
		{single, "system"},
		{filepath.Join(dir, "missing"), "x"},
	}
	got := recentConfigFiles(context.Background(), roots, now, 48*time.Hour, 100)
	paths := map[string]FileChange{}
	for _, fc := range got {
		paths[fc.Path] = fc
	}
	if len(got) != 3 {
		t.Fatalf("want app.conf, its symlink and hosts; got %d: %+v", len(got), got)
	}
	if fc, ok := paths[fresh]; !ok || fc.Area != "nginx" || fc.Symlink {
		t.Errorf("fresh conf missing or wrong: %+v", fc)
	}
	if fc, ok := paths[link]; !ok || !fc.Symlink {
		t.Errorf("enabled-site symlink should be reported as a symlink: %+v", fc)
	}
	if fc, ok := paths[single]; !ok || fc.Area != "system" {
		t.Errorf("single-file root missing: %+v", fc)
	}
	// Newest first.
	for i := 1; i < len(got); i++ {
		if got[i-1].ModifiedAt < got[i].ModifiedAt {
			t.Errorf("not sorted newest first: %v", got)
		}
	}
	if capped := recentConfigFiles(context.Background(), roots, now, 48*time.Hour, 1); len(capped) != 1 {
		t.Errorf("limit not applied: %d", len(capped))
	}
}

func TestChangesCollectorNewLinesWithoutBuffer(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dpkg.log")
	_ = os.WriteFile(p, []byte("2026-10-18 10:00:01 install a:amd64 <none> 1\n2026-10-18 10:00:02 install b:amd64 <none> 1\n"), 0o644)
	c := NewChangesCollector(nil)
	lines, first := c.newLines(p)
	if !first || len(lines) != 2 {
		t.Fatalf("first read of a file: first=%v lines=%d", first, len(lines))
	}
}
