package collectors

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"url credentials", `SQLSTATE[HY000] connecting to mysql://app:S3cr3tPw@db.internal:3306/shop`, `SQLSTATE[HY000] connecting to mysql://[user]:[password]@db.internal:3306/shop`},
		{"authorization header", `upstream sent Authorization: Bearer abcdef123456.xyz`, `upstream sent Authorization: [redacted]`},
		{"aws key id", `using key AKIAABCDEFGHIJKLMNOP for s3`, `using key [token] for s3`},
		{"github token", `push failed ghp_abcdefghijklmnopqrstuvwxyz0123456789`, `push failed [token]`},
		{"query string token", `"GET /api/hook?token=abc123def&id=7 HTTP/1.1" 500`, `"GET /api/hook?token=[redacted]&id=7 HTTP/1.1" 500`},
		{"json password", `payload {"user":"x","password":"hunter22"}`, `payload {"user":"x","password":"[redacted]"}`},
		{"php array", `'api_key' => 'k-9981'`, `'api_key' => '[redacted]'`},
		{"cli flag", `ran backup --password hunter22 --db shop`, `ran backup --password [redacted] --db shop`},
		{"mysql -p", `mysqldump -uroot -phunter22 shop`, `mysqldump -uroot -p[redacted] shop`},
		{"email", `mail to jane.doe@example.com bounced`, `mail to [email] bounced`},
		{"long hex", `session 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 expired`, `session [token] expired`},
		{"kept boolean", `password_required=true`, `password_required=true`},
		{"jwt", `bad token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`, `bad token [token]`},
	}
	for _, c := range cases {
		if got := RedactSecrets(c.in); got != c.want {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}

// Ordinary diagnostic lines must come through unchanged — IPs, ports, paths,
// times and short ids are what the explanation is built from.
func TestRedactSecretsKeepsDiagnostics(t *testing.T) {
	lines := []string{
		`2026/10/10 09:12:01 [error] 812#812: *1 connect() failed (111: Connection refused) while connecting to upstream, client: 203.0.113.9, server: shop.example, upstream: "http://127.0.0.1:9000/"`,
		`[2026-10-10 09:12:01] production.ERROR: Redis connection [tcp://10.0.0.5:6379] refused`,
		`Out of memory: Killed process 4121 (php-fpm) total-vm:812345kB`,
		`EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2: comm systemd`,
	}
	for _, l := range lines {
		if got := RedactSecrets(l); got != l {
			t.Errorf("changed a diagnostic line:\n in  %q\n out %q", l, got)
		}
	}
}

func TestRedactSecretsPrivateKey(t *testing.T) {
	in := "loaded key -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY----- ok"
	got := RedactSecrets(in)
	if strings.Contains(got, "MIIE") || !strings.Contains(got, "[PRIVATE KEY]") {
		t.Fatalf("private key not masked: %q", got)
	}
}

func TestRedactEntriesBeforeHash(t *testing.T) {
	e := []LogEntry{{Source: "systemd", Message: "login password=hunter22"}}
	redactEntries(e)
	if e[0].Message != "login password=[redacted]" {
		t.Fatalf("got %q", e[0].Message)
	}
}

// Crontabs and process command lines are shipped as raw text, so the secrets
// people type inline there must be gone before the snapshot leaves the box.
func TestRedactLines_CrontabAndCmdline(t *testing.T) {
	cron := "# user: deploy\n" +
		"0 3 * * * mysqldump -uroot -pS3cret shop > /backup/shop.sql\n" +
		"15 3 * * * AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY aws s3 sync /backup s3://b\n"
	got := redactLines(cron)
	for _, leak := range []string{"S3cret", "wJalrXUtnFEMI"} {
		if strings.Contains(got, leak) {
			t.Errorf("crontab still contains %q:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "-p[redacted] shop") || !strings.Contains(got, "AWS_SECRET_ACCESS_KEY=[redacted] aws") {
		t.Errorf("unexpected masking:\n%s", got)
	}
	if !strings.HasPrefix(got, "# user: deploy\n") {
		t.Errorf("harmless header changed:\n%s", got)
	}
	if got := RedactSecrets("mysql -uapp -pHunter2 -h db shop"); got != "mysql -uapp -p[redacted] -h db shop" {
		t.Errorf("cmdline: %q", got)
	}
}

func TestMaskWhoLine(t *testing.T) {
	cases := map[string]string{
		"shanky   pts/0        2026-10-15 10:02 (203.0.113.7)":         "sh**** pts/0 2026-10-15 10:02 (203.0.*.*)",
		"root     tty1         2026-10-14 08:00":                       "ro** tty1 2026-10-14 08:00",
		"deploy   pts/1        2026-10-15 09:30 (2001:db8:1234::5)":    "de**** pts/1 2026-10-15 09:30 (2001:db8:*)",
		"jane     pts/2        2026-10-15 11:00 (bastion.example.com)": "ja** pts/2 2026-10-15 11:00 (bastion.example.com)",
		"":    "",
		"   ": "",
	}
	for in, want := range cases {
		if got := maskWhoLine(in); got != want {
			t.Errorf("maskWhoLine(%q) = %q, want %q", in, got, want)
		}
	}
	if got := maskKeyComment("jane.doe@MacBook"); got != "ja******@MacBook" {
		t.Errorf("maskKeyComment = %q", got)
	}
	if got := maskKeyComment("deploy-ci"); got != "de*******" {
		t.Errorf("maskKeyComment = %q", got)
	}
}
