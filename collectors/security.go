package collectors

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// securityCmdTimeout bounds every external command the security collector runs,
// so a hung `journalctl`/`ufw`/`last` can never stall a heartbeat.
const securityCmdTimeout = 5 * time.Second

// dangerousPorts maps datastore ports that should never be exposed to the
// public internet to a human-readable service name.
var dangerousPorts = map[uint32]string{
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	27017: "MongoDB",
	9200:  "Elasticsearch",
}

// knownMalwareNames are process names associated with cryptominers, reverse
// shells, and similar host compromise indicators.
var knownMalwareNames = map[string]bool{
	"gsocket":    true,
	"xmrig":      true,
	"minerd":     true,
	"kdevtmpfsi": true,
}

// ── Output shapes ─────────────────────────────────────────────────────────────

type DangerousPort struct {
	Port      uint32 `json:"port"`
	Service   string `json:"service"`
	ExposedTo string `json:"exposed_to"`
}

type SSHSource struct {
	// IP is masked to its network prefix (see maskIP) — no full host address is stored.
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

type FailedSSH struct {
	CountLastHour int         `json:"count_last_hour"`
	TopSources    []SSHSource `json:"top_sources"`
}

type SuspiciousProcess struct {
	PID     int32  `json:"pid"`
	Name    string `json:"name"`
	Cmdline string `json:"cmdline"`
	Reason  string `json:"reason"`
}

type RecentLogin struct {
	// User + FromIP are masked (see maskUser / maskIP) so no full PII is stored.
	User      string `json:"user"`
	FromIP    string `json:"from_ip"`
	Timestamp string `json:"timestamp"`
}

// SecurityReport is the full output of the security collector. The score is
// computed here (0-100) so the agent ships a self-contained risk snapshot.
type SecurityReport struct {
	DangerousPorts      []DangerousPort     `json:"dangerous_ports"`
	FailedSSH           FailedSSH           `json:"failed_ssh"`
	RootLoginPermitted  bool                `json:"root_login_permitted"`
	FirewallEnabled     bool                `json:"firewall_enabled"`
	SuspiciousProcesses []SuspiciousProcess `json:"suspicious_processes"`
	RecentLogins        []RecentLogin       `json:"recent_logins"`
	// SSH hardening (from sshd_config). Pointers: nil when the config can't be
	// read, so the OHS rules stay dormant rather than assuming a default.
	SSHPasswordAuth         *bool `json:"ssh_password_auth,omitempty"`
	SSHPermitEmptyPasswords *bool `json:"ssh_permit_empty_passwords,omitempty"`
	SSHWeakCiphers          *bool `json:"ssh_weak_ciphers,omitempty"`
	// Extra hardening signals (pointers: nil when undeterminable → OHS rule dormant).
	Fail2banActive      *bool `json:"fail2ban_active,omitempty"`       // fail2ban/sshguard/crowdsec running
	AutoSecurityUpdates *bool `json:"auto_security_updates,omitempty"` // unattended-upgrades / dnf-automatic on
	PasswordlessSudo    *bool `json:"passwordless_sudo,omitempty"`     // a NOPASSWD sudoers entry exists
	// TCP ports the host firewall drops/rejects for every source on input
	// (iptables incl. ufw's chains, nftables). Lets the API accept "firewall the
	// port" as a fix for an exposed dev server. Read-only; see firewallports.go.
	FirewallBlockedPorts []int     `json:"firewall_blocked_ports,omitempty"`
	Score                int       `json:"score"`
	CollectedAt          time.Time `json:"collected_at"`
}

// SecurityCollector inspects the host for common, actionable security risks.
// Every probe is best-effort and individually recovered, so a missing tool or a
// failing command degrades that one signal rather than crashing the agent.
type SecurityCollector struct{}

func NewSecurityCollector() *SecurityCollector { return &SecurityCollector{} }
func (s *SecurityCollector) Name() string      { return "security" }

func (s *SecurityCollector) Collect(ctx context.Context) (interface{}, error) {
	report := &SecurityReport{
		DangerousPorts:      []DangerousPort{},
		SuspiciousProcesses: []SuspiciousProcess{},
		RecentLogins:        []RecentLogin{},
		CollectedAt:         time.Now().UTC(),
	}

	report.DangerousPorts = secSafe("dangerous_ports", func() []DangerousPort { return exposedDangerousPorts(ctx) })
	report.FailedSSH = secSafeVal("failed_ssh", FailedSSH{}, func() FailedSSH { return failedSSHLogins(ctx) })
	report.RootLoginPermitted = secSafeVal("root_login", false, func() bool { return rootLoginPermitted() })
	report.FirewallEnabled = secSafeVal("firewall", false, func() bool { return firewallEnabled(ctx) })
	report.SuspiciousProcesses = secSafe("suspicious_procs", func() []SuspiciousProcess { return suspiciousProcesses(ctx) })
	report.RecentLogins = secSafe("recent_logins", func() []RecentLogin { return recentLogins(ctx) })

	// SSH hardening — parsed once from sshd_config (nil when unreadable → dormant).
	if h := secSafeVal("ssh_hardening", sshHardening{}, sshHardeningFromConfig); h.readable {
		pw, empty, weak := h.passwordAuth, h.permitEmpty, h.weakCiphers
		report.SSHPasswordAuth = &pw
		report.SSHPermitEmptyPasswords = &empty
		report.SSHWeakCiphers = &weak
	}

	// Extra hardening signals — each nil when undeterminable, so its OHS rule
	// stays dormant rather than assuming a default.
	report.Fail2banActive = secSafeVal[*bool]("fail2ban", nil, func() *bool { return bruteForceGuardActive(ctx) })
	report.AutoSecurityUpdates = secSafeVal[*bool]("auto_updates", nil, func() *bool { return autoSecurityUpdates(ctx) })
	report.PasswordlessSudo = secSafeVal[*bool]("passwordless_sudo", nil, passwordlessSudo)
	report.FirewallBlockedPorts = secSafe("firewall_blocked_ports", func() []int { return firewallBlockedPorts(ctx) })

	report.Score = securityScore(report)
	return report, nil
}

// secSafe runs a slice-returning probe, converting a panic into a logged warning
// and an empty result so one bad probe cannot crash the collector.
func secSafe[T any](name string, fn func() []T) (out []T) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("security probe panicked", "probe", name, "panic", r)
			out = nil
		}
	}()
	return fn()
}

// secSafeVal is secSafe for a scalar probe, returning a fallback on panic.
func secSafeVal[T any](name string, fallback T, fn func() T) (out T) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("security probe panicked", "probe", name, "panic", r)
			out = fallback
		}
	}()
	return fn()
}

// ── Scoring (pure, unit-tested) ───────────────────────────────────────────────

// securityScore computes a 0-100 risk score. Higher is safer.
func securityScore(r *SecurityReport) int {
	score := 100
	if r.RootLoginPermitted {
		score -= 30
	}
	if !r.FirewallEnabled {
		score -= 20
	}
	// -15 per exposed dangerous port, capped at -30.
	portPenalty := 15 * len(r.DangerousPorts)
	if portPenalty > 30 {
		portPenalty = 30
	}
	score -= portPenalty
	if len(r.SuspiciousProcesses) > 0 {
		score -= 25
	}
	if r.FailedSSH.CountLastHour > 50 {
		score -= 10
	}
	if score < 0 {
		score = 0
	}
	return score
}

// ── Dangerous ports ───────────────────────────────────────────────────────────

// exposedDangerousPorts lists datastore ports that are listening on a non-loopback
// address (i.e. reachable from off-host), cross-referencing live listening sockets.
func exposedDangerousPorts(ctx context.Context) []DangerousPort {
	conns, err := net.ConnectionsWithContext(ctx, "inet")
	if err != nil {
		return nil
	}
	seen := make(map[uint32]bool)
	var out []DangerousPort
	for _, c := range conns {
		if c.Status != "LISTEN" {
			continue
		}
		service, dangerous := dangerousPorts[c.Laddr.Port]
		if !dangerous || seen[c.Laddr.Port] {
			continue
		}
		if isLoopbackAddr(c.Laddr.IP) {
			continue // bound to localhost only — not externally exposed
		}
		seen[c.Laddr.Port] = true
		out = append(out, DangerousPort{
			Port:      c.Laddr.Port,
			Service:   service,
			ExposedTo: c.Laddr.IP,
		})
	}
	return out
}

func isLoopbackAddr(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127.")
}

// ── Failed SSH logins ─────────────────────────────────────────────────────────

var sshFromIPRe = regexp.MustCompile(`from (\d{1,3}(?:\.\d{1,3}){3})`)

func failedSSHLogins(ctx context.Context) FailedSSH {
	if !hasBinary("journalctl") {
		return FailedSSH{}
	}
	out, err := runCmdTimeout(ctx, securityCmdTimeout, "journalctl",
		"-u", "ssh", "-u", "sshd", "--since", "1 hour ago", "--no-pager", "-o", "json")
	if err != nil {
		return FailedSSH{}
	}

	byIP := make(map[string]int)
	total := 0
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var j struct {
			Message string `json:"MESSAGE"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &j); err != nil {
			continue
		}
		if !strings.Contains(j.Message, "Failed password") && !strings.Contains(j.Message, "Invalid user") {
			continue
		}
		total++
		if m := sshFromIPRe.FindStringSubmatch(j.Message); m != nil {
			byIP[m[1]]++
		}
	}

	return FailedSSH{
		CountLastHour: total,
		TopSources:    topSources(byIP, 5),
	}
}

// maskIP removes host-level PII from a source IP while keeping the network
// prefix, so "many attempts from one network" is still visible. IPv4 keeps the
// first two octets (a /16); IPv6 keeps the first two hextets.
func maskIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if strings.Contains(ip, ":") { // IPv6
		parts := strings.Split(ip, ":")
		if len(parts) >= 2 {
			return parts[0] + ":" + parts[1] + ":*"
		}
		return "*"
	}
	octs := strings.Split(ip, ".")
	if len(octs) == 4 {
		return octs[0] + "." + octs[1] + ".*.*"
	}
	return ip // not a plain IPv4 (e.g. a hostname) — leave as-is
}

// maskUser keeps the first two characters of a login name and redacts the rest,
// so a personal username isn't stored in full while accounts stay distinguishable.
func maskUser(u string) string {
	u = strings.TrimSpace(u)
	if len(u) <= 2 {
		return u
	}
	return u[:2] + strings.Repeat("*", len(u)-2)
}

// topSources returns the n highest-count IPs, descending (ties broken by IP).
// Sorting happens on the RAW IP for a deterministic tie-break; the IP is masked
// only in the returned value, so two hosts sharing a /16 can't collide the order.
func topSources(byIP map[string]int, n int) []SSHSource {
	type entry struct {
		ip    string
		count int
	}
	arr := make([]entry, 0, len(byIP))
	for ip, count := range byIP {
		arr = append(arr, entry{ip, count})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].count != arr[j].count {
			return arr[i].count > arr[j].count
		}
		return arr[i].ip < arr[j].ip
	})
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]SSHSource, len(arr))
	for i, e := range arr {
		out[i] = SSHSource{IP: maskIP(e.ip), Count: e.count}
	}
	return out
}

// ── Root login policy ─────────────────────────────────────────────────────────

// rootLoginPermitted reports whether sshd is configured to allow direct root
// login via password (PermitRootLogin yes). The OpenSSH default
// ("prohibit-password") and "no" are treated as not permitted.
func rootLoginPermitted() bool {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return false
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "PermitRootLogin") {
			return strings.EqualFold(fields[1], "yes")
		}
	}
	return false
}

// ── SSH hardening (sshd_config) ────────────────────────────────────────────────

type sshHardening struct {
	readable     bool
	passwordAuth bool // PasswordAuthentication (OpenSSH default: yes)
	permitEmpty  bool // PermitEmptyPasswords (default: no)
	weakCiphers  bool // an explicit Ciphers/MACs line offering legacy algorithms
}

func sshHardeningFromConfig() sshHardening {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return sshHardening{readable: false}
	}
	return parseSSHHardening(string(data))
}

// parseSSHHardening reads sshd_config text and returns the hardening-relevant
// settings, applying OpenSSH defaults for directives that are absent. Pure and
// testable. The last matching directive wins (sshd's "first match wins" only
// applies inside Match blocks, which we conservatively ignore).
func parseSSHHardening(config string) sshHardening {
	h := sshHardening{readable: true, passwordAuth: true, permitEmpty: false, weakCiphers: false}
	weakAlgo := regexp.MustCompile(`(?i)\b(3des|arcfour|blowfish|cast128|des-cbc|hmac-md5|hmac-sha1\b|umac-64|diffie-hellman-group1-)`)
	for _, raw := range strings.Split(config, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key, val := strings.ToLower(fields[0]), strings.ToLower(fields[1])
		switch key {
		case "passwordauthentication":
			h.passwordAuth = val == "yes"
		case "permitemptypasswords":
			h.permitEmpty = val == "yes"
		case "ciphers", "macs", "kexalgorithms":
			if weakAlgo.MatchString(line) {
				h.weakCiphers = true
			}
		}
	}
	return h
}

// ── Brute-force guard (fail2ban / sshguard / crowdsec) ─────────────────────────

// bruteForceGuardActive reports whether an SSH brute-force protector is running.
// Returns nil only when we genuinely can't tell (no systemctl and no known
// client binary); a known-but-stopped guard is a definite false.
func bruteForceGuardActive(ctx context.Context) *bool {
	if hasBinary("systemctl") {
		for _, unit := range []string{"fail2ban", "sshguard", "crowdsec"} {
			out, _ := runCmdTimeout(ctx, securityCmdTimeout, "systemctl", "is-active", unit)
			if strings.TrimSpace(string(out)) == "active" {
				b := true
				return &b
			}
		}
		b := false
		return &b
	}
	// No systemd: fall back to fail2ban's own client if present.
	if hasBinary("fail2ban-client") {
		out, err := runCmdTimeout(ctx, securityCmdTimeout, "fail2ban-client", "ping")
		b := err == nil && strings.Contains(strings.ToLower(string(out)), "pong")
		return &b
	}
	return nil
}

// ── Automatic security updates ─────────────────────────────────────────────────

// autoSecurityUpdates reports whether the OS is set to install security updates
// on its own (Debian/Ubuntu unattended-upgrades, or RHEL/Fedora dnf-automatic).
// nil when the distro's package tooling isn't recognised.
func autoSecurityUpdates(ctx context.Context) *bool {
	// Debian/Ubuntu: APT::Periodic::Unattended-Upgrade "1" enables it.
	if data, err := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
		on := regexp.MustCompile(`(?i)Unattended-Upgrade"?\s+"1"`).MatchString(string(data))
		return &on
	}
	// RHEL/Fedora: a dnf-automatic (or legacy yum-cron) timer must be active.
	if hasBinary("systemctl") {
		for _, unit := range []string{"dnf-automatic-install.timer", "dnf-automatic.timer", "yum-cron"} {
			out, _ := runCmdTimeout(ctx, securityCmdTimeout, "systemctl", "is-active", unit)
			if strings.TrimSpace(string(out)) == "active" {
				b := true
				return &b
			}
		}
		if hasBinary("dnf") || hasBinary("yum") {
			b := false
			return &b
		}
	}
	// apt is present but 20auto-upgrades is missing → not configured.
	if hasBinary("apt-get") {
		b := false
		return &b
	}
	return nil
}

// ── Passwordless sudo ──────────────────────────────────────────────────────────

// opservoSudoersFile is the sudoers drop-in the remote-actions remediation flow
// (the Opservo API's sudo-password-wall remediation) writes to, scoped to
// the exact command(s) the agent needs. A NOPASSWD entry in this file is
// expected, admin-approved infrastructure — it should never be reported as a
// security finding. NOPASSWD:ALL in this file (or anywhere else) still is.
const opservoSudoersFile = "opservo-actions"

// nopasswdCommandRe captures the command spec after "NOPASSWD:" on a sudoers
// line, e.g. "user ALL=(root) NOPASSWD: /bin/systemctl restart nginx".
var nopasswdCommandRe = regexp.MustCompile(`NOPASSWD:\s*(.+)$`)

// sudoersFileHasUnscopedNopasswd reports whether a sudoers file's content
// contains a NOPASSWD grant that counts as a security finding: any NOPASSWD
// line in a file other than opservoSudoersFile, or a NOPASSWD:ALL line even
// inside opservoSudoersFile. A commented-out line doesn't count. Pure and
// unit-tested independent of the filesystem.
func sudoersFileHasUnscopedNopasswd(fileName string, data []byte) bool {
	scoped := fileName == opservoSudoersFile
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "NOPASSWD") {
			continue
		}
		if scoped {
			if m := nopasswdCommandRe.FindStringSubmatch(line); m != nil {
				cmds := strings.TrimSpace(m[1])
				if cmds != "ALL" && !strings.HasPrefix(cmds, "ALL,") && !strings.HasPrefix(cmds, "ALL ") {
					continue // scoped opservo-actions grant — sanctioned, not a finding
				}
			}
		}
		return true
	}
	return false
}

// passwordlessSudo reports whether any sudoers entry grants NOPASSWD for
// something broader than the scoped opservo-actions grant (blanket NOPASSWD:ALL
// anywhere, or NOPASSWD in any other file, always counts). nil when no sudoers
// files are readable (needs root).
func passwordlessSudo() *bool {
	readAny := false
	found := false
	if data, err := os.ReadFile("/etc/sudoers"); err == nil {
		readAny = true
		found = found || sudoersFileHasUnscopedNopasswd("sudoers", data)
	}
	if entries, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		readAny = true
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if data, err := os.ReadFile("/etc/sudoers.d/" + e.Name()); err == nil {
				found = found || sudoersFileHasUnscopedNopasswd(e.Name(), data)
			}
		}
	}
	if !readAny {
		return nil
	}
	return &found
}

// ── Firewall ──────────────────────────────────────────────────────────────────

func firewallEnabled(ctx context.Context) bool {
	if hasBinary("ufw") {
		if out, err := runCmdTimeout(ctx, securityCmdTimeout, "ufw", "status"); err == nil {
			if strings.Contains(strings.ToLower(string(out)), "status: active") {
				return true
			}
			// ufw is present and answered, but inactive — trust that.
			if strings.Contains(strings.ToLower(string(out)), "status: inactive") {
				return false
			}
		}
	}
	// Fallback: inspect iptables INPUT chain for a default-deny policy or any
	// drop/reject rules.
	if hasBinary("iptables") {
		if out, err := runCmdTimeout(ctx, securityCmdTimeout, "iptables", "-L", "INPUT", "--line-numbers", "-n"); err == nil {
			return iptablesHasFiltering(string(out))
		}
	}
	return false
}

// iptablesHasFiltering reports whether the INPUT chain enforces anything: a
// non-ACCEPT default policy, or at least one DROP/REJECT rule.
func iptablesHasFiltering(out string) bool {
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Chain INPUT") {
			if strings.Contains(line, "policy DROP") || strings.Contains(line, "policy REJECT") {
				return true
			}
			continue
		}
		if strings.Contains(line, "DROP") || strings.Contains(line, "REJECT") {
			return true
		}
	}
	return false
}

// ── Suspicious processes ──────────────────────────────────────────────────────

func suspiciousProcesses(ctx context.Context) []SuspiciousProcess {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil
	}
	var out []SuspiciousProcess
	for _, p := range procs {
		name, _ := p.NameWithContext(ctx)
		cmdline, _ := p.CmdlineWithContext(ctx)
		exe, _ := p.ExeWithContext(ctx)

		reason := suspicionReason(p.Pid, name, exe, cmdline)
		if reason == "" {
			continue
		}
		out = append(out, SuspiciousProcess{
			PID:     p.Pid,
			Name:    name,
			Cmdline: truncate(RedactSecrets(cmdline)),
			Reason:  reason,
		})
	}
	return out
}

// suspicionReason returns a non-empty reason if a process matches a known-bad
// pattern, or "" if it looks benign.
func suspicionReason(pid int32, name, exe, cmdline string) string {
	lname := strings.ToLower(name)
	if knownMalwareNames[lname] {
		return "process name matches known cryptominer/malware: " + name
	}
	// kthreadd is a genuine kernel thread that is always PID 2; any other PID
	// using that name is masquerading.
	if lname == "kthreadd" && pid != 2 {
		return "process masquerading as the kernel thread kthreadd"
	}
	// Executables launched from /tmp (or a .tmp binary) are a classic dropper
	// indicator.
	if runsFromTmp(exe) || runsFromTmp(firstField(cmdline)) {
		return "executable is running from /tmp"
	}
	return ""
}

func runsFromTmp(path string) bool {
	if path == "" {
		return false
	}
	return strings.HasPrefix(path, "/tmp/") || strings.HasSuffix(path, ".tmp")
}

func firstField(s string) string {
	fields := strings.Fields(s)
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// ── Recent successful logins ──────────────────────────────────────────────────

func recentLogins(ctx context.Context) []RecentLogin {
	if !hasBinary("last") {
		return nil
	}
	out, err := runCmdTimeout(ctx, securityCmdTimeout, "last", "-n", "5", "-w")
	if err != nil {
		return nil
	}
	return parseLastOutput(string(out))
}

// lastTimestampRe locates the date/time portion of a `last` line by pattern
// rather than by fixed column position, so it works across the layouts we've
// seen in practice:
//   - GNU coreutils/util-linux `last -w` (Debian/Ubuntu): "Tue Jun 24 10:00"
//   - RHEL/CentOS `last -w`, which on some util-linux builds appends seconds
//     and/or a trailing year: "Tue Jun 24 10:00:00 2026"
//   - BusyBox `last` (Alpine): BusyBox's loginutils/last.c formats the
//     timestamp the same weekday/month/day/time way (it doesn't reliably
//     honor `-w`, but the date rendering itself matches classic `last`); this
//     assumption is based on reading BusyBox's applet source, not a live
//     Alpine box, so the regex intentionally tolerates the optional
//     seconds/year fields rather than pinning an exact width.
var lastTimestampRe = regexp.MustCompile(`(?i)\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\w*\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s+\d{1,2}\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s+\d{4})?`)

// parseLastOutput parses `last` (with or without `-w`) output into recent
// login records. It does not assume a fixed column layout — GNU last -w
// (Debian/Ubuntu, RHEL/CentOS) and BusyBox last (Alpine) space/format their
// columns differently — so it locates the timestamp via regex and only
// treats tokens preceding the timestamp as possible host/IP candidates.
// Lines that don't look like a real login record (reboot/shutdown/wtmp
// footers, or anything too sparse to trust) are skipped rather than guessed
// at, consistent with this file's per-probe "degrade, don't crash" approach.
func parseLastOutput(out string) []RecentLogin {
	var logins []RecentLogin
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		login, ok := parseLastLine(line)
		if !ok {
			continue
		}
		logins = append(logins, login)
	}
	return logins
}

// parseLastLine parses a single `last` line into a RecentLogin, or reports
// ok=false if the line isn't a login record (footer/header/garbage).
func parseLastLine(line string) (RecentLogin, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return RecentLogin{}, false
	}
	user := fields[0]
	switch user {
	case "reboot", "shutdown", "wtmp", "btmp":
		return RecentLogin{}, false
	}
	if strings.HasPrefix(line, "wtmp begins") || strings.HasPrefix(line, "btmp begins") {
		return RecentLogin{}, false
	}

	// Only look for a host/IP among the fields BEFORE the timestamp — a time
	// like "08:00" contains a colon and would otherwise be mistaken for an
	// IPv6-ish host by looksLikeHost.
	prefix := line
	ts := ""
	if loc := lastTimestampRe.FindStringIndex(line); loc != nil {
		prefix = line[:loc[0]]
		ts = strings.TrimSpace(line[loc[0]:loc[1]])
	}
	prefixFields := strings.Fields(prefix)

	from := ""
	for _, f := range prefixFields[1:] { // skip the user field itself
		if looksLikeHost(f) {
			from = f
			break
		}
	}

	// Not enough signal to trust this as a real login line (e.g. a stray
	// header or truncated row from an unfamiliar `last` build).
	if ts == "" && from == "" && len(prefixFields) < 2 {
		return RecentLogin{}, false
	}

	return RecentLogin{User: maskUser(user), FromIP: maskIP(from), Timestamp: ts}, true
}

// looksLikeHost is a loose check that a `last` column is a source host/IP rather
// than a tty name like "pts/0" or ":0".
func looksLikeHost(s string) bool {
	if s == "" || strings.HasPrefix(s, "pts/") || strings.HasPrefix(s, "tty") || strings.HasPrefix(s, ":") {
		return false
	}
	return strings.Contains(s, ".") || strings.Contains(s, ":")
}

// ── Command helper ────────────────────────────────────────────────────────────

// runCmdTimeout runs a command with a hard timeout layered on the collector ctx.
func runCmdTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return runCmd(cctx, name, args...)
}

// runCmdEnvTimeout is runCmdTimeout with extra child-only environment variables.
func runCmdEnvTimeout(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return runCmdEnv(cctx, env, name, args...)
}
