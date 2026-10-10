package collectors

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// AppInfo describes one detected web application.
type AppInfo struct {
	Path      string   `json:"path"`
	Name      string   `json:"name,omitempty"` // package.json/composer.json name, else dir
	Framework string   `json:"framework"`      // laravel | wordpress | nodejs | nextjs | … | php
	Version   string   `json:"version,omitempty"`
	Git       *GitInfo `json:"git,omitempty"` // linked repo (branch/commit/remote), when present
}

// AppDetectCollector scans common web roots for known application markers.
// It only reads files (never executes app code) and skips anything it cannot
// classify, so it is safe to run unconfigured on any server.
type AppDetectCollector struct{}

func NewAppDetectCollector() *AppDetectCollector { return &AppDetectCollector{} }
func (a *AppDetectCollector) Name() string       { return "appdetect" }

func (a *AppDetectCollector) Collect(ctx context.Context) (interface{}, error) {
	apps := []AppInfo{}
	seen := map[string]bool{}

	for _, dir := range candidateAppDirs() {
		if ctx.Err() != nil {
			break
		}
		if app, ok := detectApp(dir); ok && !seen[app.Path] {
			seen[app.Path] = true
			if app.Name == "" {
				app.Name = appName(dir)
			}
			if git, ok := readGitInfo(ctx, dir); ok {
				app.Git = git
			}
			apps = append(apps, app)
		}
	}
	return apps, nil
}

// maxCandidateAppDirs bounds the directory walk below so a shared-hosting box
// with thousands of client directories can't turn every heartbeat into a
// large filesystem scan.
const maxCandidateAppDirs = 2000

// candidateAppDirs returns the web roots to inspect: /var/www and each
// /home/*/public_html, plus their subdirectories two levels down. Two levels
// covers the common reseller/shared-hosting layout where each customer gets
// their own directory (e.g. /var/www/clients/client1), one level deeper than
// a single app root (e.g. /var/www/myapp).
func candidateAppDirs() []string {
	var bases []string
	bases = append(bases, "/var/www")
	if matches, err := filepath.Glob("/home/*/public_html"); err == nil {
		bases = append(bases, matches...)
	}
	return candidateAppDirsFrom(bases)
}

// candidateAppDirsFrom does the actual two-level walk; split out from
// candidateAppDirs so tests can pass a temp-dir base instead of real
// filesystem roots.
func candidateAppDirsFrom(bases []string) []string {
	var dirs []string
	add := func(dir string) bool {
		if len(dirs) >= maxCandidateAppDirs {
			return false
		}
		dirs = append(dirs, dir)
		return true
	}

	for _, base := range bases {
		info, err := os.Stat(base)
		if err != nil || !info.IsDir() {
			continue
		}
		if !add(base) {
			return dirs
		}
		for _, level1 := range subDirs(base) {
			if !add(level1) {
				return dirs
			}
			for _, level2 := range subDirs(level1) {
				if !add(level2) {
					return dirs
				}
			}
		}
	}
	return dirs
}

// subDirs returns the immediate subdirectories of dir, or nil if it cannot
// be read (missing, not a directory, permission denied).
func subDirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// detectApp classifies a single directory. Order matters: Laravel and
// WordPress both contain an index.php, so their specific markers are checked
// before the plain-PHP fallback.
func detectApp(dir string) (AppInfo, bool) {
	switch {
	case fileExists(filepath.Join(dir, "artisan")):
		return AppInfo{Path: dir, Framework: "laravel", Version: laravelVersion(dir)}, true

	case fileExists(filepath.Join(dir, "wp-config.php")):
		return AppInfo{Path: dir, Framework: "wordpress", Version: wordpressVersion(dir)}, true
	}

	if fw, ver, ok := nodeFramework(dir); ok {
		return AppInfo{Path: dir, Framework: fw, Version: ver}, true
	}
	if fw, ver, ok := pythonFramework(dir); ok {
		return AppInfo{Path: dir, Framework: fw, Version: ver}, true
	}
	if fw, ver, ok := rubyFramework(dir); ok {
		return AppInfo{Path: dir, Framework: fw, Version: ver}, true
	}
	if fw, ver, ok := javaFramework(dir); ok {
		return AppInfo{Path: dir, Framework: fw, Version: ver}, true
	}
	if fw, ver, ok := goFramework(dir); ok {
		return AppInfo{Path: dir, Framework: fw, Version: ver}, true
	}

	if fileExists(filepath.Join(dir, "index.php")) {
		return AppInfo{Path: dir, Framework: "php"}, true
	}
	return AppInfo{}, false
}

// ── version helpers ──────────────────────────────────────────────────────────

var (
	laravelVerRe = regexp.MustCompile(`"laravel/framework"\s*:\s*"([^"]+)"`)
	wpVerRe      = regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)
)

func laravelVersion(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "composer.json"))
	if err != nil {
		return ""
	}
	if m := laravelVerRe.FindSubmatch(data); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

func wordpressVersion(dir string) string {
	// version.php lives under wp-includes; fall back to empty if absent.
	data, err := os.ReadFile(filepath.Join(dir, "wp-includes", "version.php"))
	if err != nil {
		return ""
	}
	if m := wpVerRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// nodePkg is the subset of package.json we read (never executed).
type nodePkg struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func readNodePkg(dir string) (*nodePkg, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil, false
	}
	var pkg nodePkg
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, false
	}
	return &pkg, true
}

// nodeDepToFramework maps a telltale dependency to a framework label, most
// specific first (a Next app also depends on react, so Next must win).
var nodeDepToFramework = []struct{ dep, framework string }{
	{"next", "nextjs"},
	{"nuxt", "nuxt"},
	{"@angular/core", "angular"},
	{"@sveltejs/kit", "sveltekit"},
	{"@nestjs/core", "nestjs"},
	{"astro", "astro"},
	{"gatsby", "gatsby"},
	{"remix", "remix"},
	{"vite", "vite"},
	{"react-scripts", "react"},
	{"react", "react"},
	{"vue", "vue"},
	{"express", "nodejs"},
	{"fastify", "nodejs"},
}

// nodeFramework classifies a Node app from package.json. The version reported is
// the app's own package version when set, else the framework dependency's range.
func nodeFramework(dir string) (string, string, bool) {
	pkg, ok := readNodePkg(dir)
	if !ok {
		return "", "", false
	}
	dep := func(name string) (string, bool) {
		if v, ok := pkg.Dependencies[name]; ok {
			return v, true
		}
		v, ok := pkg.DevDependencies[name]
		return v, ok
	}
	for _, m := range nodeDepToFramework {
		if v, ok := dep(m.dep); ok {
			ver := pkg.Version
			if ver == "" {
				ver = m.dep + "@" + v
			}
			return m.framework, ver, true
		}
	}
	return "", "", false
}

// appName derives a human name for an app from its package/composer manifest,
// falling back to the directory basename. Never reads .env or app secrets.
func appName(dir string) string {
	if pkg, ok := readNodePkg(dir); ok && pkg.Name != "" {
		return pkg.Name
	}
	if data, err := os.ReadFile(filepath.Join(dir, "composer.json")); err == nil {
		var c struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(data, &c) == nil && c.Name != "" {
			return c.Name
		}
	}
	return filepath.Base(dir)
}

// pythonFramework inspects requirements.txt for django or fastapi.
func pythonFramework(dir string) (string, string, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		return "", "", false
	}
	lines := strings.Split(string(data), "\n")
	for _, target := range []string{"django", "fastapi", "flask"} {
		for _, line := range lines {
			clean := strings.TrimSpace(strings.ToLower(line))
			if clean == "" || strings.HasPrefix(clean, "#") {
				continue
			}
			// Match the package name at the start of the requirement spec.
			name := requirementName(clean)
			if name == target {
				return target, requirementVersion(line), true
			}
		}
	}
	return "", "", false
}

var reqSplitRe = regexp.MustCompile(`[<>=!~ \[]`)

// requirementName extracts the package name from a requirements.txt line.
func requirementName(line string) string {
	idx := reqSplitRe.FindStringIndex(line)
	if idx == nil {
		return line
	}
	return line[:idx[0]]
}

// requirementVersionRe matches a version number after any PEP 508 comparison
// operator (==, ===, >=, <=, ~=, !=), so an unpinned-but-bounded requirement
// like "django>=4.2,<5.0" still yields "4.2" instead of an empty string.
var requirementVersionRe = regexp.MustCompile(`(?:==|===|>=|<=|~=|!=)\s*([0-9][0-9A-Za-z.\-+]*)`)

// requirementVersion extracts the first version constraint present, if any.
func requirementVersion(line string) string {
	if m := requirementVersionRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}

var railsVerRe = regexp.MustCompile(`(?m)^\s*rails\s*\(([^)]+)\)`)

// rubyFramework inspects Gemfile for a rails gem, falling back to generic
// ruby when a Gemfile is present but rails is not declared. The Rails version
// is read from Gemfile.lock (format "rails (X.Y.Z)") when available; for
// plain Ruby apps, the interpreter version is read from .ruby-version or the
// Gemfile's own "ruby 'X.Y.Z'" directive. Like the other detectors here, an
// unversioned match still counts as a detection.
func rubyFramework(dir string) (string, string, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "Gemfile"))
	if err != nil {
		return "", "", false
	}
	if railsGemRe.Match(data) {
		return "rails", railsVersion(dir), true
	}
	return "ruby", rubyVersion(dir, data), true
}

var rubyVersionRe = regexp.MustCompile(`(?m)^\s*ruby\s+["']([\d.]+)["']`)

// rubyVersion reports the interpreter version for a plain (non-Rails) Ruby
// app: .ruby-version takes precedence (it is the convention rbenv/asdf/CI
// tooling reads), falling back to a "ruby 'X.Y.Z'" line in the Gemfile.
func rubyVersion(dir string, gemfile []byte) string {
	if data, err := os.ReadFile(filepath.Join(dir, ".ruby-version")); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			return v
		}
	}
	if m := rubyVersionRe.FindSubmatch(gemfile); m != nil {
		return string(m[1])
	}
	return ""
}

var railsGemRe = regexp.MustCompile(`(?m)^\s*gem\s+["']rails["']`)

func railsVersion(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "Gemfile.lock"))
	if err != nil {
		return ""
	}
	if m := railsVerRe.FindSubmatch(data); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

var (
	springBootRe           = regexp.MustCompile(`spring-boot`)
	pomParentSpringBootRe  = regexp.MustCompile(`(?s)<parent>.*?<artifactId>\s*spring-boot-starter-parent\s*</artifactId>.*?<version>\s*([^<\s]+)\s*</version>`)
	pomProjectVersionRe    = regexp.MustCompile(`(?s)^.*?<project[^>]*>.*?<version>\s*([^<\s]+)\s*</version>`)
	gradleSpringBootPlugin = regexp.MustCompile(`org\.springframework\.boot['"]\s*\)?\s*version\s*['"]([^'"]+)['"]`)
	gradleProjectVersionRe = regexp.MustCompile(`(?m)^\s*version\s*=?\s*['"]([^'"]+)['"]`)
)

// javaFramework inspects Maven (pom.xml) or Gradle (build.gradle[.kts]) build
// files for a spring-boot dependency, falling back to generic java/maven or
// java/gradle when the build file is present but Spring Boot isn't detected.
// Version extraction is best-effort regex matching (not a full XML/Groovy
// parse) — it prefers the Spring Boot parent/plugin version when present,
// else the project's own declared version, else empty.
func javaFramework(dir string) (string, string, bool) {
	if data, err := os.ReadFile(filepath.Join(dir, "pom.xml")); err == nil {
		if springBootRe.Match(data) {
			return "spring-boot", pomVersion(data), true
		}
		return "java-maven", pomVersion(data), true
	}
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if springBootRe.Match(data) {
			return "spring-boot", gradleVersion(data), true
		}
		return "java-gradle", gradleVersion(data), true
	}
	return "", "", false
}

// pomVersion prefers the Spring Boot parent's <version> (the framework
// version users care about); falls back to the project's own <version>.
func pomVersion(data []byte) string {
	if m := pomParentSpringBootRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	if m := pomProjectVersionRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// gradleVersion prefers the Spring Boot plugin version; falls back to the
// project's own "version = '…'" declaration.
func gradleVersion(data []byte) string {
	if m := gradleSpringBootPlugin.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	if m := gradleProjectVersionRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

var (
	goModuleRe  = regexp.MustCompile(`(?m)^module\s+(\S+)`)
	goVersionRe = regexp.MustCompile(`(?m)^go\s+(\d+\.\d+(\.\d+)?)`)
)

// goFramework inspects go.mod for the module path. Detection is presence-only;
// there is no dominant Go web framework to disambiguate the way Node/Python
// have, so the reported version is just the "go X.Y" toolchain directive
// (empty when absent, matching the graceful-degradation convention above).
func goFramework(dir string) (string, string, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return "", "", false
	}
	if !goModuleRe.Match(data) {
		return "", "", false
	}
	version := ""
	if m := goVersionRe.FindSubmatch(data); m != nil {
		version = string(m[1])
	}
	return "go", version, true
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
