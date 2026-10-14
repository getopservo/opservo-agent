package collectors

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// gitStatusTimeout bounds `git status`. It walks the whole work tree, so on a
// big checkout (node_modules, vendor) 2 s was not always enough — and a timeout
// used to read as "clean", closing the drift finding for one heartbeat.
const gitStatusTimeout = 5 * time.Second

// lastDirty remembers each work tree's last successfully read dirty state, so a
// `git status` that times out reports the previous answer (flagged unknown)
// instead of nothing.
var (
	lastDirtyMu sync.Mutex
	lastDirty   = map[string]bool{}
)

// GitInfo describes the git repository an app or dev-server lives in. Branch,
// commit and remote are read directly from files under .git (no binary, no
// network, no secrets). Commit time + dirty are a best-effort bonus from the
// git binary when it is installed.
type GitInfo struct {
	Branch      string `json:"branch,omitempty"`
	Commit      string `json:"commit,omitempty"`       // short sha (12 chars)
	Remote      string `json:"remote,omitempty"`       // origin URL, host/org/repo (creds stripped)
	CommittedAt string `json:"committed_at,omitempty"` // ISO-8601 of HEAD commit (deploy freshness)
	Dirty       *bool  `json:"dirty,omitempty"`        // uncommitted changes in the work tree (drift)
	// DirtyUnknown: `git status` timed out / failed this time. Dirty then
	// carries the last known value (if any) — never a fresh "clean".
	DirtyUnknown bool `json:"dirty_unknown,omitempty"`
}

// readGitInfo walks up from dir (a few levels) to find a git work tree and
// extracts its branch, commit, and origin remote. Returns false when dir is not
// inside a repository.
func readGitInfo(ctx context.Context, dir string) (*GitInfo, bool) {
	gitDir, ok := findGitDir(dir)
	if !ok {
		return nil, false
	}

	head, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return nil, false
	}
	gi := &GitInfo{}
	h := strings.TrimSpace(string(head))
	if ref := strings.TrimSpace(strings.TrimPrefix(h, "ref:")); strings.HasPrefix(h, "ref:") {
		gi.Branch = strings.TrimPrefix(ref, "refs/heads/")
		gi.Commit = shortSHA(resolveRef(gitDir, ref))
		if gi.Commit == "" {
			gi.Commit = shortSHA(resolveRef(commonGitDir(gitDir), ref))
		}
	} else {
		gi.Branch = "(detached)"
		gi.Commit = shortSHA(h)
	}
	gi.Remote = normalizeRemote(originURL(gitDir))
	if gi.Remote == "" {
		gi.Remote = normalizeRemote(originURL(commonGitDir(gitDir)))
	}

	// Deploy freshness + drift — best-effort via the git binary (may be absent).
	if ts, ok := gitCLI(ctx, dir, "log", "-1", "--format=%cI"); ok && ts != "" {
		gi.CommittedAt = ts
	}
	if st, ok := gitCLITimeout(ctx, gitStatusTimeout, dir, "status", "--porcelain"); ok {
		dirty := st != ""
		gi.Dirty = &dirty
		rememberDirty(gitDir, dirty)
	} else if hasBinary("git") {
		gi.Dirty, gi.DirtyUnknown = recallDirty(gitDir), true
	}

	if gi.Commit == "" && gi.Branch == "" && gi.Remote == "" {
		return nil, false
	}
	return gi, true
}

// gitCLI runs a read-only git command in workdir with a short timeout.
// safe.directory=* avoids "dubious ownership" errors when the repo is owned by
// a different user than the agent. Returns false if git is missing or errors.
func gitCLI(ctx context.Context, workdir string, args ...string) (string, bool) {
	return gitCLITimeout(ctx, 2*time.Second, workdir, args...)
}

// gitCLITimeout is gitCLI with an explicit timeout.
//
// GIT_OPTIONAL_LOCKS=0: `git status` otherwise takes .git/index.lock to refresh
// the index, and when the timeout kills it that lock is left behind (owned by
// root, since the agent runs as root), so the owner's next `git pull` or deploy
// fails. Set as an env var, not --no-optional-locks: git older than 2.15 (e.g.
// CentOS 7) rejects the flag but ignores the variable.
func gitCLITimeout(ctx context.Context, timeout time.Duration, workdir string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	full := append([]string{"-C", workdir, "-c", "safe.directory=*"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// findGitDir returns the resolved .git directory for the work tree containing
// dir, searching dir and up to 4 parent levels. Handles both a normal .git
// directory and a .git *file* (worktrees/submodules: "gitdir: <path>").
func findGitDir(dir string) (string, bool) {
	d := dir
	for i := 0; i < 5 && d != "" && d != "/"; i++ {
		p := filepath.Join(d, ".git")
		if info, err := os.Stat(p); err == nil {
			if info.IsDir() {
				return p, true
			}
			// .git file → points elsewhere (worktree/submodule).
			if data, err := os.ReadFile(p); err == nil {
				line := strings.TrimSpace(string(data))
				if gp := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:")); strings.HasPrefix(line, "gitdir:") {
					if !filepath.IsAbs(gp) {
						gp = filepath.Join(d, gp)
					}
					return gp, true
				}
			}
		}
		d = filepath.Dir(d)
	}
	return "", false
}

// commonGitDir returns the shared repository directory for a linked worktree
// (whose per-worktree gitdir holds HEAD but not refs/config — those live in the
// directory named by its "commondir" file). For a normal .git dir it returns
// gitDir unchanged.
func commonGitDir(gitDir string) string {
	data, err := os.ReadFile(filepath.Join(gitDir, "commondir"))
	if err != nil {
		return gitDir
	}
	cd := strings.TrimSpace(string(data))
	if cd == "" {
		return gitDir
	}
	if !filepath.IsAbs(cd) {
		cd = filepath.Join(gitDir, cd)
	}
	return filepath.Clean(cd)
}

// resolveRef returns the commit sha a symbolic ref points to, checking the loose
// ref file first, then packed-refs.
func resolveRef(gitDir, ref string) string {
	if data, err := os.ReadFile(filepath.Join(gitDir, filepath.FromSlash(ref))); err == nil {
		return strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile(filepath.Join(gitDir, "packed-refs")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
				continue
			}
			if fields := strings.Fields(line); len(fields) == 2 && fields[1] == ref {
				return fields[0]
			}
		}
	}
	return ""
}

// originURL extracts the origin remote's fetch URL from .git/config.
func originURL(gitDir string) string {
	data, err := os.ReadFile(filepath.Join(gitDir, "config"))
	if err != nil {
		return ""
	}
	inOrigin := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			inOrigin = strings.HasPrefix(line, `[remote "origin"]`)
			continue
		}
		if inOrigin && strings.HasPrefix(line, "url") {
			if i := strings.Index(line, "="); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

func shortSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// normalizeRemote turns a git remote URL into a compact host/org/repo form,
// stripping any embedded credentials and the trailing ".git".
func normalizeRemote(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}
	// scp-style: git@github.com:org/repo.git
	if strings.HasPrefix(url, "git@") || (strings.Contains(url, "@") && !strings.Contains(url, "://")) {
		if i := strings.Index(url, "@"); i >= 0 {
			url = url[i+1:]
		}
		url = strings.Replace(url, ":", "/", 1)
	} else {
		// https://user:token@host/org/repo.git → drop scheme + creds
		if i := strings.Index(url, "://"); i >= 0 {
			url = url[i+3:]
		}
		if i := strings.Index(url, "@"); i >= 0 {
			url = url[i+1:]
		}
	}
	return strings.TrimSuffix(url, ".git")
}

func rememberDirty(gitDir string, dirty bool) {
	lastDirtyMu.Lock()
	lastDirty[gitDir] = dirty
	lastDirtyMu.Unlock()
}

// recallDirty returns the last successfully read dirty state for a work tree,
// or nil when it has never been read (first heartbeat after start).
func recallDirty(gitDir string) *bool {
	lastDirtyMu.Lock()
	defer lastDirtyMu.Unlock()
	if v, ok := lastDirty[gitDir]; ok {
		return &v
	}
	return nil
}
