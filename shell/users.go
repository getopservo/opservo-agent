package shell

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Account is a local user a session can run as.
type Account struct {
	Name  string
	UID   uint32
	GID   uint32
	Home  string
	Shell string
}

// noLogin reports shells that mean "this account can't log in".
func noLogin(sh string) bool {
	base := filepath.Base(sh)
	return sh == "" || base == "nologin" || base == "false" || base == "sync" || base == "halt" || base == "shutdown"
}

// parsePasswd reads /etc/passwd-format lines. Pure for tests.
func parsePasswd(r io.Reader) []Account {
	var out []Account
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err1 := strconv.ParseUint(f[2], 10, 32)
		gid, err2 := strconv.ParseUint(f[3], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, Account{Name: f[0], UID: uint32(uid), GID: uint32(gid), Home: f[5], Shell: f[6]})
	}
	return out
}

// loginAccounts keeps root and regular users (uid ≥ 1000, not nobody) that
// have a real login shell — the people a person might want a terminal as.
func loginAccounts(all []Account) []Account {
	var out []Account
	for _, a := range all {
		if noLogin(a.Shell) || a.Name == "nobody" {
			continue
		}
		if a.UID == 0 || (a.UID >= 1000 && a.UID < 65534) {
			out = append(out, a)
		}
	}
	return out
}

// LoginUsers lists the names the dashboard may offer for this server.
func LoginUsers() []string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	var names []string
	for _, a := range loginAccounts(parsePasswd(f)) {
		names = append(names, a.Name)
	}
	return names
}

// lookupAccount resolves a session's user. Only login-capable accounts are
// allowed, so a session can't be opened as a system/service account.
func lookupAccount(name string) (Account, []uint32, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return Account{}, nil, fmt.Errorf("read /etc/passwd: %w", err)
	}
	defer f.Close()
	for _, a := range loginAccounts(parsePasswd(f)) {
		if a.Name != name {
			continue
		}
		var groups []uint32
		if u, err := user.Lookup(name); err == nil {
			if ids, err := u.GroupIds(); err == nil {
				for _, g := range ids {
					if n, err := strconv.ParseUint(g, 10, 32); err == nil {
						groups = append(groups, uint32(n))
					}
				}
			}
		}
		return a, groups, nil
	}
	return Account{}, nil, fmt.Errorf("%q is not a login user on this server", name)
}
