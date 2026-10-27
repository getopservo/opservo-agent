package collectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Server software versions (27 Oct 2026). Which version of cloudflared,
// nginx, Docker, Redis, OpenSSH … is installed, and HOW it was installed —
// the API compares the version with the latest release and known security
// advisories, and the install method decides the update command (an apt
// package upgrades with apt; a binary dropped in /usr/local/bin does not).
// Prompted by a Cloudflare advisory for cloudflared < 2026.10.2: our own tunnel
// binary lived in /usr/local/bin, so the package-update collector never saw it.
//
// Read-only: each probe runs a fixed binary with a fixed version flag, and the
// package lookup only asks dpkg/rpm who owns the file. Results are cached per
// binary (path + size + mtime), so a probe re-runs only when the file changes
// — right after an update, never every heartbeat.

// SoftwareInfo is one installed copy of a tracked program.
type SoftwareInfo struct {
	ID      string `json:"id"`   // catalogue key: "cloudflared", "nginx", …
	Name    string `json:"name"` // display name
	Version string `json:"version,omitempty"`
	Path    string `json:"path"`
	// Install: "apt" | "rpm" (owned by a package), "snap", or "binary" (a file
	// nothing manages — updated by its own tool or by replacing the file).
	Install        string `json:"install"`
	Package        string `json:"package,omitempty"`
	PackageVersion string `json:"package_version,omitempty"` // full distro version, e.g. 1:9.6p1-3ubuntu13.5
}

type softwareProbe struct {
	id, name string
	bins     []string // names looked up on PATH, then in softwareDirs
	globs    []string // extra absolute globs (versioned install dirs)
	args     []string
}

// softwareDirs: the agent's service PATH can miss the sbin dirs and
// /usr/local, which is exactly where hand-installed binaries live.
var softwareDirs = []string{"/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/snap/bin"}

var softwareProbes = []softwareProbe{
	{id: "cloudflared", name: "cloudflared", bins: []string{"cloudflared"}, args: []string{"--version"}},
	{id: "nginx", name: "nginx", bins: []string{"nginx"}, args: []string{"-v"}},
	{id: "apache", name: "Apache httpd", bins: []string{"apache2", "httpd"}, args: []string{"-v"}},
	{id: "caddy", name: "Caddy", bins: []string{"caddy"}, args: []string{"version"}},
	{id: "haproxy", name: "HAProxy", bins: []string{"haproxy"}, args: []string{"-v"}},
	{id: "traefik", name: "Traefik", bins: []string{"traefik"}, args: []string{"version"}},
	{id: "docker", name: "Docker", bins: []string{"docker"}, args: []string{"--version"}},
	{id: "containerd", name: "containerd", bins: []string{"containerd"}, args: []string{"--version"}},
	{id: "redis", name: "Redis", bins: []string{"redis-server"}, args: []string{"--version"}},
	{id: "mysql", name: "MySQL", bins: []string{"mysqld"}, args: []string{"--version"}},
	{id: "postgres", name: "PostgreSQL", bins: []string{"postgres"}, globs: []string{"/usr/lib/postgresql/*/bin/postgres", "/usr/pgsql-*/bin/postgres"}, args: []string{"--version"}},
	{id: "mongodb", name: "MongoDB", bins: []string{"mongod"}, args: []string{"--version"}},
	{id: "openssh", name: "OpenSSH", bins: []string{"sshd"}, args: []string{"-V"}},
	{id: "openssl", name: "OpenSSL", bins: []string{"openssl"}, args: []string{"version"}},
	{id: "sudo", name: "sudo", bins: []string{"sudo"}, args: []string{"--version"}},
	{id: "git", name: "Git", bins: []string{"git"}, args: []string{"--version"}},
	{id: "certbot", name: "Certbot", bins: []string{"certbot"}, args: []string{"--version"}},
	{id: "kubectl", name: "kubectl", bins: []string{"kubectl"}, args: []string{"version", "--client"}},
	{id: "helm", name: "Helm", bins: []string{"helm"}, args: []string{"version", "--short"}},
	{id: "tailscale", name: "Tailscale", bins: []string{"tailscale"}, args: []string{"version"}},
}

// softwareVersionRe: the first dotted version in the output, keeping an
// OpenSSH-style portable suffix (9.6p1) and calendar versions (2026.10.2).
var softwareVersionRe = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?(?:p\d+)?`)

// SoftwareCollector reports tracked server software and its versions.
type SoftwareCollector struct{}

func NewSoftwareCollector() *SoftwareCollector { return &SoftwareCollector{} }
func (s *SoftwareCollector) Name() string      { return "software" }

// A binary's facts change only when the file does; the TTL just bounds memory
// for files that were replaced long ago.
const softwareCacheTTL = 24 * time.Hour

func (s *SoftwareCollector) Collect(ctx context.Context) (interface{}, error) {
	type found struct {
		probe softwareProbe
		path  string
	}
	var todo []found
	seen := map[string]bool{}
	for _, p := range softwareProbes {
		for _, path := range locateSoftware(p) {
			if !seen[path] {
				seen[path] = true
				todo = append(todo, found{p, path})
			}
		}
	}

	// Probes run in parallel (bounded): a cold cache on a busy box must still
	// finish inside the registry's per-collector deadline.
	out := make([]SoftwareInfo, len(todo))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, f := range todo {
		wg.Add(1)
		go func(i int, f found) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = probeSoftware(ctx, f.probe, f.path)
		}(i, f)
	}
	wg.Wait()

	res := make([]SoftwareInfo, 0, len(out))
	for _, si := range out {
		if si.ID != "" {
			res = append(res, si)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].ID != res[j].ID {
			return res[i].ID < res[j].ID
		}
		return res[i].Path < res[j].Path
	})
	return res, nil
}

// locateSoftware returns the distinct real paths of a probe's binaries.
func locateSoftware(p softwareProbe) []string {
	var cands []string
	for _, b := range p.bins {
		if lp, err := exec.LookPath(b); err == nil {
			cands = append(cands, lp)
		}
		for _, d := range softwareDirs {
			cands = append(cands, filepath.Join(d, b))
		}
	}
	for _, g := range p.globs {
		m, _ := filepath.Glob(g)
		cands = append(cands, m...)
	}
	var paths []string
	seen := map[string]bool{}
	for _, c := range cands {
		real, err := filepath.EvalSymlinks(c)
		if err != nil {
			continue
		}
		st, err := os.Stat(real)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 || seen[real] {
			continue
		}
		seen[real] = true
		paths = append(paths, real)
	}
	return paths
}

func probeSoftware(ctx context.Context, p softwareProbe, path string) SoftwareInfo {
	st, err := os.Stat(path)
	if err != nil {
		return SoftwareInfo{}
	}
	key := fmt.Sprintf("software\x00%s\x00%d\x00%d", path, st.Size(), st.ModTime().UnixNano())
	raw, _ := cachedRun(key, softwareCacheTTL, func() ([]byte, error) {
		si := SoftwareInfo{ID: p.id, Name: p.name, Path: path}
		text := versionOutput(ctx, path, p.args)
		si.Version = softwareVersionRe.FindString(text)
		// MariaDB ships a mysqld too; it is a different product with its own releases.
		if p.id == "mysql" && strings.Contains(strings.ToLower(text), "mariadb") {
			si.ID, si.Name = "mariadb", "MariaDB"
		}
		si.Install, si.Package, si.PackageVersion = installMethod(ctx, path)
		return json.Marshal(si)
	})
	var si SoftwareInfo
	if json.Unmarshal(raw, &si) != nil {
		return SoftwareInfo{}
	}
	return si
}

// versionOutput runs `<path> <args>` and returns stdout+stderr (nginx, sshd
// and Apache print their version on stderr; sshd -V also exits non-zero).
func versionOutput(ctx context.Context, path string, args []string) string {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	_ = cmd.Run()
	if buf.Len() > 4096 {
		buf.Truncate(4096)
	}
	return buf.String()
}

// installMethod says who manages a binary: a dpkg/rpm package (with its full
// version, which carries the distro's backported-fix suffix), a snap, or nobody.
func installMethod(ctx context.Context, path string) (method, pkg, pkgVersion string) {
	if strings.HasPrefix(path, "/snap/") {
		return "snap", "", ""
	}
	if hasBinary("dpkg-query") {
		if pkg = dpkgOwner(ctx, path); pkg != "" {
			out, _ := runCmdTimeout(ctx, 4*time.Second, "dpkg-query", "-W", "-f=${Version}", pkg)
			return "apt", pkg, strings.TrimSpace(string(out))
		}
	}
	if hasBinary("rpm") {
		out, err := runCmdTimeout(ctx, 4*time.Second, "rpm", "-qf", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n", path)
		if line := strings.TrimSpace(firstLine(string(out))); err == nil && strings.Contains(line, "\t") {
			parts := strings.SplitN(line, "\t", 2)
			return "rpm", parts[0], parts[1]
		}
	}
	return "binary", "", ""
}

// dpkgOwner: `dpkg-query -S` matches the path as installed, which on merged-/usr
// systems may be /bin/x rather than the /usr/bin/x we resolved — try both.
func dpkgOwner(ctx context.Context, path string) string {
	tries := []string{path}
	if strings.HasPrefix(path, "/usr/") {
		tries = append(tries, strings.TrimPrefix(path, "/usr"))
	}
	for _, t := range tries {
		out, err := runCmdTimeout(ctx, 4*time.Second, "dpkg-query", "-S", t)
		if err != nil {
			continue
		}
		if pkg := parseDpkgOwner(string(out), t); pkg != "" {
			return pkg
		}
	}
	return ""
}

// parseDpkgOwner reads `pkg[:arch][, pkg2]: /path` lines and returns the first
// package that owns exactly that path (diversions are skipped).
func parseDpkgOwner(out, path string) string {
	for _, line := range strings.Split(out, "\n") {
		i := strings.LastIndex(line, ": ")
		if i < 0 || strings.TrimSpace(line[i+2:]) != path || strings.HasPrefix(line, "diversion ") {
			continue
		}
		pkg := strings.TrimSpace(strings.Split(line[:i], ",")[0])
		if j := strings.IndexByte(pkg, ':'); j >= 0 {
			pkg = pkg[:j]
		}
		return pkg
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
