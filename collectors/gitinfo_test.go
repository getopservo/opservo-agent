package collectors

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeRemote(t *testing.T) {
	cases := map[string]string{
		"git@github.com:example-org/example-app.git":     "github.com/example-org/example-app",
		"https://github.com/example-org/example-app.git": "github.com/example-org/example-app",
		"https://user:token@gitlab.com/team/app.git":     "gitlab.com/team/app",
		"ssh://git@bitbucket.org/team/app":               "bitbucket.org/team/app",
		"":                                               "",
	}
	for in, want := range cases {
		if got := normalizeRemote(in); got != want {
			t.Errorf("normalizeRemote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadGitInfo_ThisRepo(t *testing.T) {
	// Walk up to the repo root (where .git lives) from the test's cwd.
	wd, _ := os.Getwd()
	if _, ok := findGitDir(wd); !ok {
		t.Skip("not running inside a git checkout")
	}
	gi, ok := readGitInfo(context.Background(), wd)
	if !ok {
		t.Fatal("expected git info for the repo checkout")
	}
	if gi.Commit == "" {
		t.Error("expected a commit sha")
	}
	if gi.Branch == "" {
		t.Error("expected a branch")
	}
}

func TestReadGitInfo_NotARepo(t *testing.T) {
	dir := t.TempDir()
	// Ensure no ancestor .git interferes by pointing deep into an isolated tmp.
	sub := filepath.Join(dir, "a", "b")
	_ = os.MkdirAll(sub, 0o755)
	if _, ok := findGitDir(sub); ok {
		t.Skip("tmp dir unexpectedly inside a repo")
	}
	if _, ok := readGitInfo(context.Background(), sub); ok {
		t.Error("expected no git info outside a repo")
	}
}

// A `git status` that fails/times out must read as "unknown" carrying the last
// known answer — never as a clean tree (that closed CFG_DRIFT_001 for a beat).
func TestReadGitInfo_StatusFailureIsUnknownNotClean(t *testing.T) {
	if !hasBinary("git") {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@t", "-c", "user.name=t"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "a.txt")
	run("commit", "-q", "-m", "init")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}

	gi, ok := readGitInfo(context.Background(), dir)
	if !ok || gi.Dirty == nil || !*gi.Dirty || gi.DirtyUnknown {
		t.Fatalf("first read: %+v, want dirty=true known", gi)
	}

	// Cancelled context → git status cannot run.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	gi, ok = readGitInfo(ctx, dir)
	if !ok || !gi.DirtyUnknown || gi.Dirty == nil || !*gi.Dirty {
		t.Fatalf("failed read: %+v, want dirty_unknown with the last known dirty=true", gi)
	}
}

// The agent must never write to a repo it reads. A plain `git status` refreshes
// stale stat info by rewriting .git/index under .git/index.lock; a killed git
// leaves that lock behind and blocks the owner's next pull (prod, 8 + 14 Oct
// 2026). The agent's git calls must leave the index untouched.
func TestGitCLI_DoesNotWriteTheIndex(t *testing.T) {
	if !hasBinary("git") {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@t", "-c", "user.name=t"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v %s", args, err, out)
		}
	}
	file := filepath.Join(dir, "a.txt")
	index := filepath.Join(dir, ".git", "index")
	// staleIndex moves a.txt's mtime so the index's stat info is out of date
	// and the next `git status` wants to refresh it; returns the index bytes.
	stamp := time.Now().Add(-time.Hour)
	staleIndex := func() []byte {
		stamp = stamp.Add(time.Minute)
		if err := os.Chtimes(file, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(index)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	run("init", "-q")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "a.txt")
	run("commit", "-q", "-m", "init")

	// Control: a plain git status does rewrite the index here; if this git
	// doesn't, the check below proves nothing.
	before := staleIndex()
	run("status", "--porcelain")
	if after, _ := os.ReadFile(index); string(after) == string(before) {
		t.Skip("this git does not refresh the index on status")
	}

	before = staleIndex()
	if _, ok := gitCLITimeout(context.Background(), gitStatusTimeout, dir, "status", "--porcelain"); !ok {
		t.Fatal("git status failed")
	}
	if after, _ := os.ReadFile(index); string(after) != string(before) {
		t.Fatal("the agent's git status rewrote .git/index; it must run with GIT_OPTIONAL_LOCKS=0")
	}
	if _, err := os.Stat(index + ".lock"); err == nil {
		t.Fatal("index.lock left behind")
	}
}

func TestRecallDirty_NeverReadIsNil(t *testing.T) {
	if recallDirty("/nonexistent/.git") != nil {
		t.Fatal("a work tree never read must not invent a value")
	}
}
