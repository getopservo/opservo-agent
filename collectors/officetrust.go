package collectors

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/getopservo/opservo-agent/trust"
)

// ── Office addresses (12 Nov 2026) ────────────────────────────────────────────
//
// A failed `sudo -n` (no password) lands in the journal as an error and became
// a "recurring error" alert, although on office machines it is almost always a
// colleague who SSHed in from the office. The sudo line carries no source
// address, so trust can only come from tying it to SSH sessions on this box.
// When the workspace has office addresses set, the agent reports a summary of
// the last hour: how many sudo password failures there were, how many SSH
// sessions were open, and whether every one of them — and every user whose
// sudo failed — came from an office address. The API decides what to do with
// it (fewer than 5 failures and everything trusted → no alert). Matching uses
// the FULL source address here, before maskIP(); nothing unmasked is sent.

// officeTrustWindowMinutes is the sudo-failure window the summary covers. A
// little over the API's one-hour log window, so every failure the API still
// counts for a finding has been seen (and its user checked) here.
const officeTrustWindowMinutes = 70

// OfficeTrust is the per-heartbeat summary. Only present when the workspace
// has office addresses set (nil otherwise → API behaves as before).
type OfficeTrust struct {
	// ListHash identifies the office-address list used (trust.Hash); the API
	// ignores the summary unless it matches the workspace's current list.
	ListHash      string `json:"list_hash"`
	WindowMinutes int    `json:"window_minutes"`
	// SudoAuthFailures counts failed sudo authentications in the window
	// ("a password is required", "N incorrect password attempts",
	// pam_unix(sudo:auth) authentication failures).
	SudoAuthFailures int `json:"sudo_auth_failures"`
	// SSHSessions is the number of distinct (user, source) SSH sessions
	// accepted in the last two hours or still open now.
	SSHSessions       int `json:"ssh_sessions"`
	UntrustedSessions int `json:"untrusted_sessions"`
	// AllSessionsTrusted: at least one SSH session and none from outside the
	// office addresses.
	AllSessionsTrusted bool `json:"all_sessions_trusted"`
	// SudoUsersTrusted: every user whose sudo failed has an SSH session from
	// an office address (so a web-app user like www-data probing sudo, or a
	// local console user, never counts as "office").
	SudoUsersTrusted bool `json:"sudo_users_trusted"`
}

// sshSession is one SSH login seen on the box, with its FULL source address.
type sshSession struct {
	user string
	host string
}

var (
	// "paras : a password is required ; TTY=pts/0 ; PWD=… ; USER=root ; COMMAND=…"
	// "paras : 3 incorrect password attempts ; TTY=…"
	sudoFailureRe = regexp.MustCompile(`^\s*(\S+) : (?:a password is required|\d+ incorrect password attempts?)\b`)
	// "pam_unix(sudo:auth): authentication failure; logname=paras uid=1000 euid=0 tty=/dev/pts/0 ruser=paras rhost=  user=paras"
	sudoPamFailureRe = regexp.MustCompile(`pam_unix\(sudo:auth\): authentication failure;`)
	pamRuserRe       = regexp.MustCompile(`\bruser=(\S+)`)
	pamLognameRe     = regexp.MustCompile(`\blogname=(\S+)`)
	// "Accepted publickey for paras from 192.168.1.50 port 51234 ssh2: ED25519 SHA256:…"
	sshAcceptedRe = regexp.MustCompile(`Accepted \S+ for (\S+) from (\S+) port \d+`)
)

// parseSudoFailures counts failed sudo authentications in journal messages
// and collects the users they belong to. An unattributable failure adds ""
// to the user set, which can never be matched to a trusted session.
func parseSudoFailures(msgs []string) (count int, users map[string]bool) {
	users = make(map[string]bool)
	summary, pam := 0, 0
	for _, m := range msgs {
		if sm := sudoFailureRe.FindStringSubmatch(m); sm != nil {
			summary++
			users[sm[1]] = true
			continue
		}
		if sudoPamFailureRe.MatchString(m) {
			pam++
			u := ""
			if r := pamRuserRe.FindStringSubmatch(m); r != nil {
				u = r[1]
			} else if r := pamLognameRe.FindStringSubmatch(m); r != nil {
				u = r[1]
			}
			users[u] = true
		}
	}
	// One interactive sudo logs a pam line per wrong password AND one summary
	// line; `sudo -n` logs only the summary. Take the larger, never the sum.
	count = summary
	if pam > count {
		count = pam
	}
	return count, users
}

// parseAcceptedLogins extracts successful SSH logins from sshd messages.
func parseAcceptedLogins(msgs []string) []sshSession {
	var out []sshSession
	for _, m := range msgs {
		if sm := sshAcceptedRe.FindStringSubmatch(m); sm != nil {
			out = append(out, sshSession{user: sm[1], host: sm[2]})
		}
	}
	return out
}

// parseWho extracts REMOTE sessions from `who` output:
//
//	paras    pts/0        2026-11-12 10:00 (192.168.1.50)
//
// Console logins (no host), X displays "(:0)" and tmux/screen panes are local
// and skipped. Any other host — including a hostname we can't verify — is kept
// as a remote session (and will count as untrusted).
func parseWho(out string) []sshSession {
	var res []sshSession
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasSuffix(line, ")") {
			continue
		}
		i := strings.Index(line, " (")
		if i < 0 {
			continue
		}
		host := strings.TrimSpace(line[i+2 : len(line)-1])
		if host == "" || strings.HasPrefix(host, ":") || strings.HasPrefix(host, "tmux") || strings.HasPrefix(host, "screen") {
			continue
		}
		// `who` may append ":S.0" style display suffixes to a remote host.
		if strings.Count(host, ":") == 1 && strings.Contains(host, ".") {
			host = host[:strings.IndexByte(host, ':')]
		}
		res = append(res, sshSession{user: fields[0], host: host})
	}
	return res
}

// summarizeOfficeTrust is the pure core of the office-trust summary.
func summarizeOfficeTrust(list trust.List, sudoFailures int, sudoUsers map[string]bool, sessions []sshSession) *OfficeTrust {
	seen := make(map[string]bool)
	trustedUsers := make(map[string]bool)
	total, untrusted := 0, 0
	for _, s := range sessions {
		key := s.user + "\x00" + s.host
		if seen[key] {
			continue
		}
		seen[key] = true
		total++
		if list.Contains(s.host) {
			trustedUsers[s.user] = true
		} else {
			untrusted++
		}
	}
	usersOK := true
	for u := range sudoUsers {
		if u == "" || !trustedUsers[u] {
			usersOK = false
			break
		}
	}
	return &OfficeTrust{
		ListHash:           list.Hash(),
		WindowMinutes:      officeTrustWindowMinutes,
		SudoAuthFailures:   sudoFailures,
		SSHSessions:        total,
		UntrustedSessions:  untrusted,
		AllSessionsTrusted: total > 0 && untrusted == 0,
		SudoUsersTrusted:   usersOK,
	}
}

// journalMessages runs journalctl with -o json and returns the MESSAGE fields.
func journalMessages(ctx context.Context, args ...string) ([]string, bool) {
	out, err := runCmdTimeout(ctx, securityCmdTimeout, "journalctl", append(args, "--no-pager", "-o", "json")...)
	if err != nil {
		return nil, false
	}
	var msgs []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var j struct {
			Message json.RawMessage `json:"MESSAGE"`
		}
		if json.Unmarshal(sc.Bytes(), &j) != nil {
			continue
		}
		// MESSAGE is a string, or a byte array for non-UTF-8 lines; we only
		// need the string form.
		var s string
		if json.Unmarshal(j.Message, &s) == nil {
			msgs = append(msgs, s)
		}
	}
	return msgs, true
}

// officeTrust collects the summary. Returns nil when the list is empty or the
// journal can't be read — no summary means the API alerts exactly as before.
func officeTrust(ctx context.Context, list trust.List) *OfficeTrust {
	if list.Empty() || !hasBinary("journalctl") {
		return nil
	}
	sudoMsgs, ok := journalMessages(ctx, "_COMM=sudo", "--since", strconv.Itoa(officeTrustWindowMinutes)+" minutes ago")
	if !ok {
		return nil
	}
	// Sessions: logins accepted in the last TWO hours (so a session that
	// started before the earliest failure in the window still counts) plus
	// every remote session still open now.
	sshMsgs, ok := journalMessages(ctx, "-u", "ssh", "-u", "sshd", "--since", "2 hours ago")
	if !ok {
		return nil
	}
	sessions := parseAcceptedLogins(sshMsgs)
	if hasBinary("who") {
		if out, err := runCmdTimeout(ctx, securityCmdTimeout, "who"); err == nil {
			sessions = append(sessions, parseWho(string(out))...)
		}
	}
	count, users := parseSudoFailures(sudoMsgs)
	return summarizeOfficeTrust(list, count, users, sessions)
}
