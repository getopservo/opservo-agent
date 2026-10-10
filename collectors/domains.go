package collectors

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// DomainInfo describes a virtual host and the state of its TLS certificate.
type DomainInfo struct {
	Domain          string     `json:"domain"`
	Server          string     `json:"server"` // nginx | apache
	Root            string     `json:"root,omitempty"` // vhost document root → correlate to an app
	SSLExpiry       *time.Time `json:"ssl_expiry,omitempty"`
	DaysUntilExpiry *int       `json:"days_until_expiry,omitempty"`
	SSLError        string     `json:"ssl_error,omitempty"`
}

// DomainCollector reads nginx/apache vhost configs to enumerate served domains
// and checks each domain's live TLS certificate expiry. Missing config
// directories or unreachable hosts are skipped gracefully.
type DomainCollector struct{}

func NewDomainCollector() *DomainCollector { return &DomainCollector{} }
func (d *DomainCollector) Name() string    { return "domains" }

const sslDialTimeout = 4 * time.Second

func (d *DomainCollector) Collect(ctx context.Context) (interface{}, error) {
	// domain -> server, de-duplicated across all vhost files.
	found := map[string]string{}
	for domain := range parseNginx() {
		found[domain] = "nginx"
	}
	for domain := range parseApache() {
		if _, exists := found[domain]; !exists {
			found[domain] = "apache"
		}
	}

	domains := make([]string, 0, len(found))
	for domain := range found {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	roots := vhostRoots() // domain -> document root, best-effort

	results := make([]DomainInfo, len(domains))
	sem := make(chan struct{}, 8) // bound concurrent TLS dials
	var wg sync.WaitGroup
	for i, domain := range domains {
		wg.Add(1)
		go func(i int, domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			info := checkSSL(ctx, domain, found[domain])
			info.Root = roots[domain]
			results[i] = info
		}(i, domain)
	}
	wg.Wait()

	return results, nil
}

// checkSSL dials domain:443 and reads its certificate expiry. The chain is not
// validated (InsecureSkipVerify) because we only need the NotAfter date, which
// must be readable even for self-signed or misconfigured certs.
func checkSSL(ctx context.Context, domain, server string) DomainInfo {
	info := DomainInfo{Domain: domain, Server: server}

	dialer := &net.Dialer{Timeout: sslDialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(domain, "443"), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // expiry read only, not auth
		ServerName:         domain,
	})
	if err != nil {
		info.SSLError = err.Error()
		return info
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		info.SSLError = "no certificate presented"
		return info
	}

	expiry := certs[0].NotAfter
	days := int(time.Until(expiry).Hours() / 24)
	info.SSLExpiry = &expiry
	info.DaysUntilExpiry = &days
	return info
}

// ── vhost parsing ────────────────────────────────────────────────────────────

var (
	nginxServerNameRe = regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
	apacheServerRe    = regexp.MustCompile(`(?mi)^\s*(?:ServerName|ServerAlias)\s+(.+)$`)
)

func parseNginx() map[string]struct{} {
	// sites-enabled (Debian) + conf.d (RHEL and many custom setups).
	return parseVhostGlobs(nginxServerNameRe,
		"/etc/nginx/sites-enabled/*",
		"/etc/nginx/conf.d/*.conf",
	)
}

func parseApache() map[string]struct{} {
	// Debian (apache2) + RHEL (httpd) layouts.
	return parseVhostGlobs(apacheServerRe,
		"/etc/apache2/sites-enabled/*",
		"/etc/apache2/conf.d/*.conf",
		"/etc/httpd/conf.d/*.conf",
		"/etc/httpd/conf/httpd.conf",
	)
}

// parseVhostGlobs unions the vhosts found across several config globs.
func parseVhostGlobs(re *regexp.Regexp, globs ...string) map[string]struct{} {
	domains := map[string]struct{}{}
	for _, g := range globs {
		for d := range parseVhosts(g, re) {
			domains[d] = struct{}{}
		}
	}
	return domains
}

// parseVhosts reads every config file matching glob and extracts domain names
// from the directive captured by re.
func parseVhosts(glob string, re *regexp.Regexp) map[string]struct{} {
	domains := map[string]struct{}{}
	files, err := filepath.Glob(glob)
	if err != nil {
		return domains
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, m := range re.FindAllSubmatch(data, -1) {
			for _, name := range strings.Fields(string(m[1])) {
				if isResolvableDomain(name) {
					domains[name] = struct{}{}
				}
			}
		}
	}
	return domains
}

// ── vhost document roots ─────────────────────────────────────────────────────

var (
	nginxBlockRe  = regexp.MustCompile(`^\s*server\s*\{`)
	nginxRootRe   = regexp.MustCompile(`(?m)^\s*root\s+([^;]+);`)
	apacheBlockRe = regexp.MustCompile(`(?i)^\s*<VirtualHost`)
	apacheRootRe  = regexp.MustCompile(`(?mi)^\s*DocumentRoot\s+(.+)$`)
)

// vhostRoots maps each served domain to its document root, so the API can tell
// which detected app a domain fronts. Best-effort: it pairs server_name/root
// directives within the same vhost block via a small line state machine (real
// brace parsing isn't needed just to find the root).
func vhostRoots() map[string]string {
	roots := map[string]string{}
	pairVhostRoots(roots, nginxBlockRe, nginxServerNameRe, nginxRootRe,
		"/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf")
	pairVhostRoots(roots, apacheBlockRe, apacheServerRe, apacheRootRe,
		"/etc/apache2/sites-enabled/*", "/etc/apache2/conf.d/*.conf",
		"/etc/httpd/conf.d/*.conf", "/etc/httpd/conf/httpd.conf")
	return roots
}

func pairVhostRoots(out map[string]string, blockRe, nameRe, rootRe *regexp.Regexp, globs ...string) {
	for _, g := range globs {
		files, err := filepath.Glob(g)
		if err != nil {
			continue
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			var names []string
			var root string
			flush := func() {
				if root == "" {
					return
				}
				clean := strings.TrimRight(strings.Trim(strings.TrimSpace(root), `"'`), "/")
				for _, n := range names {
					if isResolvableDomain(n) {
						if _, exists := out[n]; !exists {
							out[n] = clean
						}
					}
				}
			}
			for _, line := range strings.Split(string(data), "\n") {
				if blockRe.MatchString(line) {
					flush()
					names, root = nil, ""
				}
				if m := nameRe.FindStringSubmatch(line); m != nil {
					names = append(names, strings.Fields(m[1])...)
				}
				if m := rootRe.FindStringSubmatch(line); m != nil {
					root = m[1]
				}
			}
			flush()
		}
	}
}

// isResolvableDomain filters out placeholders and wildcards that cannot be
// dialed for a TLS check (e.g. "_", "*.example.com", "localhost").
func isResolvableDomain(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || name == "_" || name == "localhost" {
		return false
	}
	if strings.ContainsAny(name, "*$") {
		return false
	}
	return strings.Contains(name, ".")
}
