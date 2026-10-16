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
	Domain string `json:"domain"`
	Server string `json:"server"`         // nginx | apache | cloudflared (tunnel only)
	Root   string `json:"root,omitempty"` // vhost document root → correlate to an app
	// Where the vhost sends requests when it is a reverse proxy (ProxyPass /
	// proxy_pass), e.g. "http://127.0.0.1:3000" or "http://192.0.2.27:80".
	// Set when the site is served by another process or another server, so
	// the dashboard can say so instead of implying "no app here".
	Upstream string `json:"upstream,omitempty"`
	// Application root declared for an in-server app runner (PassengerAppRoot /
	// passenger_app_root), when present.
	AppRoot string `json:"app_root,omitempty"`
	// Cloudflare Tunnel service this hostname is routed to (e.g.
	// "http://localhost:8080"), when the site is published through cloudflared.
	Tunnel          string     `json:"tunnel,omitempty"`
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
	tunnels := tunnelRoutes(ctx)
	for domain := range tunnels {
		if _, exists := found[domain]; !exists {
			found[domain] = "cloudflared"
		}
	}

	domains := make([]string, 0, len(found))
	for domain := range found {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	details := vhostDetails() // domain -> root / upstream / app root, best-effort

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
			v := details[domain]
			info.Root, info.Upstream, info.AppRoot = v.Root, v.Upstream, v.AppRoot
			info.Tunnel = tunnels[domain]
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

// ── vhost document roots, proxy targets and app roots ────────────────────────

var (
	nginxBlockRe      = regexp.MustCompile(`^\s*server\s*\{`)
	nginxRootRe       = regexp.MustCompile(`^\s*root\s+([^;]+);`)
	nginxProxyRe      = regexp.MustCompile(`^\s*(?:proxy_pass|uwsgi_pass|grpc_pass)\s+([^;]+);`)
	nginxAppRootRe    = regexp.MustCompile(`^\s*passenger_app_root\s+([^;]+);`)
	apacheBlockRe     = regexp.MustCompile(`(?i)^\s*<VirtualHost`)
	apacheRootRe      = regexp.MustCompile(`(?i)^\s*DocumentRoot\s+(.+)$`)
	apacheProxyRe     = regexp.MustCompile(`(?i)^\s*ProxyPass(?:Match)?\s+(\S+)\s+(\S+)`)
	apacheAppRootRe   = regexp.MustCompile(`(?i)^\s*PassengerAppRoot\s+(.+)$`)
	urlUserinfoRe     = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@]*@`)
	nginxLocationRe   = regexp.MustCompile(`^\s*location\s`)
	nginxLocationRoot = regexp.MustCompile(`^\s*location\s+/\s*\{`)
)

// vhostDetail is what one vhost block says about where its site lives.
type vhostDetail struct {
	Root     string // DocumentRoot / root
	Upstream string // reverse-proxy target, credentials stripped
	AppRoot  string // PassengerAppRoot / passenger_app_root
}

type vhostSyntax struct {
	block, name, root, appRoot *regexp.Regexp
	// proxy returns (target, isSiteRoot) for a proxy directive line, or ok=false.
	proxy func(line string) (target string, isSiteRoot bool, ok bool)
}

var nginxSyntax = vhostSyntax{
	block: nginxBlockRe, name: nginxServerNameRe, root: nginxRootRe, appRoot: nginxAppRootRe,
	proxy: func(line string) (string, bool, bool) {
		m := nginxProxyRe.FindStringSubmatch(line)
		if m == nil {
			return "", false, false
		}
		return m[1], false, true
	},
}

var apacheSyntax = vhostSyntax{
	block: apacheBlockRe, name: apacheServerRe, root: apacheRootRe, appRoot: apacheAppRootRe,
	proxy: func(line string) (string, bool, bool) {
		m := apacheProxyRe.FindStringSubmatch(line)
		if m == nil || m[2] == "!" {
			return "", false, false
		}
		path := strings.Trim(m[1], `"'`)
		return m[2], path == "/" || path == "^/(.*)$" || path == "^/(.*)", true
	},
}

// vhostDetails maps each served domain to its document root, proxy target and
// app root, so the API can tell which detected app a domain fronts — or that
// the site is served from somewhere else. Best-effort: it pairs directives
// within the same vhost block via a small line state machine (real brace
// parsing isn't needed for this).
func vhostDetails() map[string]vhostDetail {
	out := map[string]vhostDetail{}
	pairVhostDetails(out, nginxSyntax, "/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf")
	pairVhostDetails(out, apacheSyntax,
		"/etc/apache2/sites-enabled/*", "/etc/apache2/conf.d/*.conf",
		"/etc/httpd/conf.d/*.conf", "/etc/httpd/conf/httpd.conf")
	return out
}

func pairVhostDetails(out map[string]vhostDetail, syn vhostSyntax, globs ...string) {
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
			parseVhostDetails(out, syn, string(data))
		}
	}
}

// parseVhostDetails is the pure part of pairVhostDetails (config text in,
// per-domain details out) so it can be tested without /etc.
func parseVhostDetails(out map[string]vhostDetail, syn vhostSyntax, config string) {
	var names []string
	var cur vhostDetail
	siteRootProxy := false
	inLocationRoot := false
	flush := func() {
		if cur == (vhostDetail{}) {
			return
		}
		for _, n := range names {
			if !isResolvableDomain(n) {
				continue
			}
			prev, exists := out[n]
			if !exists {
				out[n] = cur
				continue
			}
			// The same name in several blocks (port 80 redirect + 443 site):
			// fill in whatever the earlier block left empty.
			if prev.Root == "" {
				prev.Root = cur.Root
			}
			if prev.Upstream == "" {
				prev.Upstream = cur.Upstream
			}
			if prev.AppRoot == "" {
				prev.AppRoot = cur.AppRoot
			}
			out[n] = prev
		}
	}
	for _, line := range strings.Split(config, "\n") {
		if syn.block.MatchString(line) {
			flush()
			names, cur, siteRootProxy, inLocationRoot = nil, vhostDetail{}, false, false
		}
		if nginxLocationRe.MatchString(line) {
			inLocationRoot = nginxLocationRoot.MatchString(line)
		}
		if m := syn.name.FindStringSubmatch(line); m != nil {
			names = append(names, strings.Fields(m[1])...)
		}
		if m := syn.root.FindStringSubmatch(line); m != nil {
			cur.Root = cleanConfigPath(m[1])
		}
		if m := syn.appRoot.FindStringSubmatch(line); m != nil {
			cur.AppRoot = cleanConfigPath(m[1])
		}
		if target, isSiteRoot, ok := syn.proxy(line); ok {
			isSiteRoot = isSiteRoot || inLocationRoot
			// The proxy for "/" wins over one for a sub-path (/api, /ws).
			if cur.Upstream == "" || (isSiteRoot && !siteRootProxy) {
				cur.Upstream = cleanUpstream(target)
				siteRootProxy = isSiteRoot
			}
		}
	}
	flush()
}

func cleanConfigPath(v string) string {
	return strings.TrimRight(strings.Trim(strings.TrimSpace(v), `"'`), "/")
}

// cleanUpstream trims quotes and drops any user:password@ from a proxy URL —
// the agent never ships credentials.
func cleanUpstream(v string) string {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	v = urlUserinfoRe.ReplaceAllString(v, "$1")
	return strings.TrimRight(v, "/")
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
