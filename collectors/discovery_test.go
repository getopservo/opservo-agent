package collectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCPUPercentFromDelta(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	// 0.6s of CPU time over a 60s interval = 1% of one core.
	if got := cpuPercentFromDelta(
		cpuSample{usageNSec: 1_000_000_000, at: base},
		cpuSample{usageNSec: 1_600_000_000, at: base.Add(60 * time.Second)},
	); got != 1.0 {
		t.Errorf("expected 1.0%%, got %v", got)
	}
	// A full core busy for the whole interval = 100%.
	if got := cpuPercentFromDelta(
		cpuSample{usageNSec: 0, at: base},
		cpuSample{usageNSec: 60_000_000_000, at: base.Add(60 * time.Second)},
	); got != 100.0 {
		t.Errorf("expected 100.0%%, got %v", got)
	}
	// Counter reset (cur < prev) must not produce a negative or huge value.
	if got := cpuPercentFromDelta(
		cpuSample{usageNSec: 5_000_000_000, at: base},
		cpuSample{usageNSec: 1_000_000_000, at: base.Add(60 * time.Second)},
	); got != 0 {
		t.Errorf("counter reset should yield 0, got %v", got)
	}
	// Zero / non-positive interval yields 0 (no divide-by-zero).
	if got := cpuPercentFromDelta(
		cpuSample{usageNSec: 1_000_000_000, at: base},
		cpuSample{usageNSec: 2_000_000_000, at: base},
	); got != 0 {
		t.Errorf("zero interval should yield 0, got %v", got)
	}
}

func TestParseSystemdUnits(t *testing.T) {
	out := `  UNIT                 LOAD   ACTIVE SUB     DESCRIPTION
  nginx.service        loaded active running A high performance web server
  ssh.service          loaded active running OpenBSD Secure Shell server
  not-a-service.mount  loaded active mounted Some mount

2 loaded units listed.`

	units := parseSystemdUnits([]byte(out), "running")
	if len(units) != 2 {
		t.Fatalf("expected 2 service units, got %d: %+v", len(units), units)
	}
	if units[0].Name != "nginx" || units[0].Type != "systemd" || units[0].Status != "running" {
		t.Errorf("unexpected first unit: %+v", units[0])
	}
	if units[0].Description != "A high performance web server" {
		t.Errorf("description not parsed: %q", units[0].Description)
	}
}

func TestParseSystemdUnits_Empty(t *testing.T) {
	if got := parseSystemdUnits([]byte("0 loaded units listed.\n"), "failed"); len(got) != 0 {
		t.Errorf("expected no units, got %d", len(got))
	}
}

func TestCandidateAppDirsFrom(t *testing.T) {
	base := t.TempDir()
	// base/clients/client1  (level 2 — the reseller-hosting case PRD-7 targets)
	// base/myapp            (level 1 — the common single-app case)
	mustMkdir := func(p string) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustMkdir(filepath.Join(base, "clients", "client1"))
	mustMkdir(filepath.Join(base, "myapp"))

	dirs := candidateAppDirsFrom([]string{base})

	want := []string{
		base,
		filepath.Join(base, "clients"),
		filepath.Join(base, "myapp"),
		filepath.Join(base, "clients", "client1"),
	}
	got := map[string]bool{}
	for _, d := range dirs {
		got[d] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("expected %q in candidateAppDirsFrom result, got %v", w, dirs)
		}
	}
}

func TestCandidateAppDirsFrom_MissingBase(t *testing.T) {
	dirs := candidateAppDirsFrom([]string{filepath.Join(t.TempDir(), "does-not-exist")})
	if len(dirs) != 0 {
		t.Errorf("expected no dirs for a missing base, got %v", dirs)
	}
}

func TestDetectApp(t *testing.T) {
	tmp := t.TempDir()

	write := func(dir, name, content string) string {
		full := filepath.Join(tmp, dir)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		if name != "" {
			if err := os.WriteFile(filepath.Join(full, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return full
	}

	cases := []struct {
		name      string
		dir       string
		file      string
		content   string
		framework string
		version   string
	}{
		{"laravel", "laravel", "artisan", "#!/usr/bin/env php", "laravel", ""},
		{"wordpress", "wp", "wp-config.php", "<?php define('DB_NAME', 'x');", "wordpress", ""},
		{"node-express", "node", "package.json", `{"dependencies":{"express":"^4.18.2"}}`, "nodejs", "express@^4.18.2"},
		{"django", "dj", "requirements.txt", "Django==4.2.1\ngunicorn==21.0", "django", "4.2.1"},
		{"fastapi", "fa", "requirements.txt", "fastapi>=0.100.0\nuvicorn", "fastapi", "0.100.0"},
		{"plain-ruby", "ruby", "Gemfile", "source 'https://rubygems.org'\ngem 'sinatra'", "ruby", ""},
		{"go-app", "go", "go.mod", "module example.com/myapp\n\ngo 1.22\n", "go", "1.22"},
		{"java-maven", "maven", "pom.xml", "<project><artifactId>myapp</artifactId></project>", "java-maven", ""},
		{"java-maven-versioned", "maven-ver", "pom.xml", "<project><artifactId>myapp</artifactId><version>2.3.1</version></project>", "java-maven", "2.3.1"},
		{"plain-php", "php", "index.php", "<?php echo 1;", "php", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := write(tc.dir, tc.file, tc.content)
			app, ok := detectApp(dir)
			if !ok {
				t.Fatalf("expected detection for %s", tc.name)
			}
			if app.Framework != tc.framework {
				t.Errorf("framework: got %q want %q", app.Framework, tc.framework)
			}
			if app.Version != tc.version {
				t.Errorf("version: got %q want %q", app.Version, tc.version)
			}
		})
	}
}

func TestDetectApp_Rails(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile"), []byte("source 'https://rubygems.org'\ngem 'rails'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile.lock"), []byte("GEM\n  specs:\n    rails (7.1.2)\n      actioncable (= 7.1.2)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app, ok := detectApp(tmp)
	if !ok || app.Framework != "rails" {
		t.Fatalf("expected rails, got %+v (ok=%v)", app, ok)
	}
	if app.Version != "7.1.2" {
		t.Errorf("version: got %q want %q", app.Version, "7.1.2")
	}
}

func TestDetectApp_SpringBootMaven(t *testing.T) {
	tmp := t.TempDir()
	pom := `<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(tmp, "pom.xml"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}
	app, ok := detectApp(tmp)
	if !ok || app.Framework != "spring-boot" {
		t.Fatalf("expected spring-boot, got %+v (ok=%v)", app, ok)
	}
}

func TestDetectApp_SpringBootMavenVersion(t *testing.T) {
	tmp := t.TempDir()
	pom := `<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.5</version>
  </parent>
</project>`
	if err := os.WriteFile(filepath.Join(tmp, "pom.xml"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}
	app, ok := detectApp(tmp)
	if !ok || app.Framework != "spring-boot" {
		t.Fatalf("expected spring-boot, got %+v (ok=%v)", app, ok)
	}
	if app.Version != "3.2.5" {
		t.Errorf("version: got %q want %q", app.Version, "3.2.5")
	}
}

func TestDetectApp_SpringBootGradle(t *testing.T) {
	tmp := t.TempDir()
	gradle := "plugins {\n  id 'org.springframework.boot' version '3.2.0'\n}\ndependencies {\n  implementation 'org.springframework.boot:spring-boot-starter-web'\n}\n"
	if err := os.WriteFile(filepath.Join(tmp, "build.gradle"), []byte(gradle), 0o644); err != nil {
		t.Fatal(err)
	}
	app, ok := detectApp(tmp)
	if !ok || app.Framework != "spring-boot" {
		t.Fatalf("expected spring-boot, got %+v (ok=%v)", app, ok)
	}
	if app.Version != "3.2.0" {
		t.Errorf("version: got %q want %q", app.Version, "3.2.0")
	}
}

func TestDetectApp_RubyVersionFromRubyVersionFile(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile"), []byte("source 'https://rubygems.org'\ngem 'sinatra'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".ruby-version"), []byte("3.2.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app, ok := detectApp(tmp)
	if !ok || app.Framework != "ruby" {
		t.Fatalf("expected ruby, got %+v (ok=%v)", app, ok)
	}
	if app.Version != "3.2.2" {
		t.Errorf("version: got %q want %q", app.Version, "3.2.2")
	}
}

func TestDetectApp_RubyVersionFromGemfileDirective(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "Gemfile"), []byte("source 'https://rubygems.org'\nruby '3.1.4'\ngem 'sinatra'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app, ok := detectApp(tmp)
	if !ok || app.Framework != "ruby" {
		t.Fatalf("expected ruby, got %+v (ok=%v)", app, ok)
	}
	if app.Version != "3.1.4" {
		t.Errorf("version: got %q want %q", app.Version, "3.1.4")
	}
}

func TestDetectApp_LaravelBeatsPlainPHP(t *testing.T) {
	// A Laravel app also contains index.php; the artisan marker must win.
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "artisan"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "index.php"), []byte("<?php"), 0o644); err != nil {
		t.Fatal(err)
	}
	app, ok := detectApp(tmp)
	if !ok || app.Framework != "laravel" {
		t.Fatalf("expected laravel, got %+v (ok=%v)", app, ok)
	}
}

func TestDetectApp_NoMarkers(t *testing.T) {
	if _, ok := detectApp(t.TempDir()); ok {
		t.Error("expected no detection for empty dir")
	}
}

func TestIsResolvableDomain(t *testing.T) {
	cases := map[string]bool{
		"example.com":     true,
		"www.example.com": true,
		"_":               false,
		"localhost":       false,
		"*.example.com":   false,
		"example":         false,
		"":                false,
	}
	for in, want := range cases {
		if got := isResolvableDomain(in); got != want {
			t.Errorf("isResolvableDomain(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseVhosts_Nginx(t *testing.T) {
	tmp := t.TempDir()
	conf := `server {
    listen 443 ssl;
    server_name example.com www.example.com;
}
server {
    server_name _;
}`
	if err := os.WriteFile(filepath.Join(tmp, "site.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	domains := parseVhosts(filepath.Join(tmp, "*"), nginxServerNameRe)
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d: %v", len(domains), domains)
	}
	if _, ok := domains["example.com"]; !ok {
		t.Error("expected example.com")
	}
	if _, ok := domains["_"]; ok {
		t.Error("placeholder _ should be filtered out")
	}
}

func TestParseHumanBytes(t *testing.T) {
	cases := map[string]uint64{
		"123.4MiB": 129394278, // 123.4 * 1024*1024
		"2GiB":     2147483648,
		"512kB":    512000,
		"0B":       0,
		"1.5GiB":   1610612736,
	}
	for in, want := range cases {
		got := parseHumanBytes(in)
		// allow ±1 for float rounding
		if got != want && got != want-1 && got != want+1 {
			t.Errorf("parseHumanBytes(%q) = %d, want ~%d", in, got, want)
		}
	}
}
