package collectors

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getopservo/opservo-agent/trust"
)

func officeList(t *testing.T, cidrs ...string) trust.List {
	t.Helper()
	p, err := trust.Parse(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return trust.NewList(p, trust.Hash(cidrs))
}

func TestParseSudoFailures(t *testing.T) {
	cases := []struct {
		name      string
		msgs      []string
		wantCount int
		wantUsers []string
	}{
		{"sudo -n without password", []string{
			"paras : a password is required ; TTY=pts/0 ; PWD=/home/paras ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
			"paras : a password is required ; PWD=/home/paras ; USER=root ; COMMAND=/usr/bin/ls",
		}, 2, []string{"paras"}},
		{"leading spaces (sudo 1.9)", []string{
			"    paras : a password is required ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/true",
		}, 1, []string{"paras"}},
		{"interactive wrong password: pam lines + summary, not summed", []string{
			"pam_unix(sudo:auth): authentication failure; logname=paras uid=1000 euid=0 tty=/dev/pts/0 ruser=paras rhost=  user=paras",
			"pam_unix(sudo:auth): authentication failure; logname=paras uid=1000 euid=0 tty=/dev/pts/0 ruser=paras rhost=  user=paras",
			"paras : 2 incorrect password attempts ; TTY=pts/0 ; PWD=/home/paras ; USER=root ; COMMAND=/bin/bash",
		}, 2, []string{"paras"}},
		{"singular attempt", []string{
			"deploy : 1 incorrect password attempt ; TTY=pts/2 ; PWD=/srv ; USER=root ; COMMAND=/bin/ls",
		}, 1, []string{"deploy"}},
		{"pam line without user is unattributable", []string{
			"pam_unix(sudo:auth): authentication failure; uid=33 euid=0 tty= rhost=",
		}, 1, []string{""}},
		{"successful sudo and session lines are not failures", []string{
			"paras : TTY=pts/0 ; PWD=/home/paras ; USER=root ; COMMAND=/usr/bin/apt update",
			"pam_unix(sudo:session): session opened for user root(uid=0) by paras(uid=1000)",
			"paras : user NOT in sudoers ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
		}, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, users := parseSudoFailures(tc.msgs)
			if n != tc.wantCount {
				t.Errorf("count = %d, want %d", n, tc.wantCount)
			}
			if len(users) != len(tc.wantUsers) {
				t.Fatalf("users = %v, want %v", users, tc.wantUsers)
			}
			for _, u := range tc.wantUsers {
				if !users[u] {
					t.Errorf("missing user %q in %v", u, users)
				}
			}
		})
	}
}

func TestParseAcceptedLogins(t *testing.T) {
	got := parseAcceptedLogins([]string{
		"Accepted publickey for paras from 192.168.1.50 port 51234 ssh2: ED25519 SHA256:abc",
		"Accepted password for deploy from 2001:db8::7 port 40000 ssh2",
		"Failed password for root from 45.1.2.3 port 22 ssh2",
		"Invalid user admin from 45.1.2.3 port 5555",
	})
	if len(got) != 2 || got[0] != (sshSession{"paras", "192.168.1.50"}) || got[1] != (sshSession{"deploy", "2001:db8::7"}) {
		t.Fatalf("got %+v", got)
	}
}

func TestParseWho(t *testing.T) {
	out := strings.Join([]string{
		"paras    pts/0        2026-11-12 10:00 (192.168.1.50)",
		"paras    pts/1        2026-11-12 10:05 (tmux(1234).%0)",
		"shanky   tty1         2026-11-12 09:00",
		"shanky   :0           2026-11-12 09:00 (:0)",
		"ops      pts/2        2026-11-12 10:10 (203.0.113.9:S.0)",
		"vadi     pts/3        2026-11-12 10:11 (laptop.example.com)",
	}, "\n")
	got := parseWho(out)
	want := []sshSession{{"paras", "192.168.1.50"}, {"ops", "203.0.113.9"}, {"vadi", "laptop.example.com"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSummarizeOfficeTrust(t *testing.T) {
	office := officeList(t, "192.168.1.0/24")
	users := func(u ...string) map[string]bool {
		m := map[string]bool{}
		for _, x := range u {
			m[x] = true
		}
		return m
	}
	cases := []struct {
		name          string
		failures      int
		sudoUsers     map[string]bool
		sessions      []sshSession
		wantAll       bool
		wantUsers     bool
		wantSessions  int
		wantUntrusted int
	}{
		{"office login, own sudo failures", 3, users("paras"),
			[]sshSession{{"paras", "192.168.1.50"}, {"paras", "192.168.1.50"}}, true, true, 1, 0},
		{"one outside login spoils it", 2, users("paras"),
			[]sshSession{{"paras", "192.168.1.50"}, {"root", "45.1.2.3"}}, false, true, 2, 1},
		{"same /16 but outside the /24 is not trusted", 1, users("paras"),
			[]sshSession{{"paras", "192.168.2.50"}}, false, false, 1, 1},
		{"no SSH session at all", 2, users("paras"), nil, false, false, 0, 0},
		{"sudo by a user with no office session (web shell)", 1, users("www-data"),
			[]sshSession{{"paras", "192.168.1.50"}}, true, false, 1, 0},
		{"unattributable failure", 1, users(""),
			[]sshSession{{"paras", "192.168.1.50"}}, true, false, 1, 0},
		{"hostname instead of IP is untrusted", 1, users("paras"),
			[]sshSession{{"paras", "pc.office.lan"}}, false, false, 1, 1},
		{"no failures, office sessions", 0, users(),
			[]sshSession{{"paras", "192.168.1.50"}}, true, true, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := summarizeOfficeTrust(office, tc.failures, tc.sudoUsers, tc.sessions)
			if got.AllSessionsTrusted != tc.wantAll || got.SudoUsersTrusted != tc.wantUsers ||
				got.SSHSessions != tc.wantSessions || got.UntrustedSessions != tc.wantUntrusted {
				t.Fatalf("got %+v", got)
			}
			if got.SudoAuthFailures != tc.failures || got.WindowMinutes != officeTrustWindowMinutes || got.ListHash != office.Hash() {
				t.Fatalf("bookkeeping wrong: %+v", got)
			}
		})
	}
}

func TestRecentLoginsTrustedUsesFullIPThenMasks(t *testing.T) {
	out := strings.Join([]string{
		"paras    pts/0        192.168.1.50     Wed Nov 12 10:00   still logged in",
		"root     pts/1        192.168.2.50     Wed Nov 12 09:00 - 09:30  (00:30)",
		"shanky   tty1                          Wed Nov 12 08:00 - 08:10  (00:10)",
	}, "\n")

	// No office addresses → Trusted stays nil (field omitted).
	for _, l := range parseLastOutput(out) {
		if l.Trusted != nil {
			t.Fatalf("Trusted set without office addresses: %+v", l)
		}
	}

	got := parseLastOutputTrusted(out, officeList(t, "192.168.1.0/24"))
	if len(got) != 3 {
		t.Fatalf("got %d logins: %+v", len(got), got)
	}
	want := []bool{true, false, false}
	for i, l := range got {
		if l.Trusted == nil || *l.Trusted != want[i] {
			t.Errorf("[%d] trusted = %v, want %v (%+v)", i, l.Trusted, want[i], l)
		}
	}
	// Still masked on the wire: both addresses share 192.168.*.* yet only one is trusted.
	if got[0].FromIP != "192.168.*.*" || got[1].FromIP != "192.168.*.*" {
		t.Fatalf("addresses not masked: %+v", got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "192.168.1.50") {
		t.Fatalf("full address leaked: %s", b)
	}
}
