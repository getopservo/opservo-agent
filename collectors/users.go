package collectors

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"strings"
)

// SSHKey is one authorized key (the key body is never included — only its type
// and comment, which are enough to identify it).
type SSHKey struct {
	User    string `json:"user"`
	Type    string `json:"type"`
	Comment string `json:"comment"`
}

// UsersInfo: who is logged in and which SSH keys can access this server.
// Sessions are the `who` lines with the login name and source address masked
// (same maskUser/maskIP as the SSH findings) — the dashboard renders each line
// as-is, so the shape is unchanged.
type UsersInfo struct {
	Sessions []string `json:"sessions"`
	Keys     []SSHKey `json:"keys"`
}

type UsersCollector struct{}

func NewUsersCollector() *UsersCollector { return &UsersCollector{} }
func (u *UsersCollector) Name() string   { return "users" }

func (u *UsersCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &UsersInfo{Sessions: []string{}, Keys: []SSHKey{}}

	if out, err := runCmd(ctx, "who"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if l := maskWhoLine(line); l != "" {
				info.Sessions = append(info.Sessions, l)
			}
		}
	}

	// Authorized keys for root + each home directory. The agent runs privileged
	// so these files are readable.
	dirs := []string{"/root"}
	if homes, err := os.ReadDir("/home"); err == nil {
		for _, h := range homes {
			dirs = append(dirs, "/home/"+h.Name())
		}
	}
	for _, d := range dirs {
		user := d[strings.LastIndex(d, "/")+1:]
		data, err := os.ReadFile(d + "/.ssh/authorized_keys")
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 {
				continue
			}
			if !strings.HasPrefix(fields[0], "ssh-") && !strings.HasPrefix(fields[0], "ecdsa") && !strings.HasPrefix(fields[0], "sk-") {
				continue
			}
			comment := ""
			if len(fields) >= 3 {
				comment = maskKeyComment(fields[len(fields)-1])
			}
			info.Keys = append(info.Keys, SSHKey{User: user, Type: fields[0], Comment: comment})
		}
	}
	return info, nil
}

// maskWhoLine turns one `who` line ("jane pts/0 2026-10-15 10:02 (203.0.113.7)")
// into "ja** pts/0 2026-10-15 10:02 (203.0.*.*)": the login name and the
// source host are personal data; the tty and time are what the dashboard
// needs. Lines that do not look like `who` output are masked whole.
func maskWhoLine(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	if len(fields) < 2 {
		return maskUser(fields[0])
	}
	out := []string{maskUser(fields[0]), fields[1]}
	for _, f := range fields[2:] {
		if strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")") {
			f = "(" + maskIP(f[1:len(f)-1]) + ")"
		}
		out = append(out, f)
	}
	return strings.Join(out, " ")
}

// maskKeyComment masks the person in an authorized_keys comment ("jane@laptop"
// → "ja**@laptop", "deploy-ci" → "de*******") while keeping it distinguishable.
func maskKeyComment(c string) string {
	if i := strings.Index(c, "@"); i >= 0 {
		return maskUser(c[:i]) + c[i:]
	}
	return maskUser(c)
}
