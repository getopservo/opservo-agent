package collectors

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
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

func TestRecallDirty_NeverReadIsNil(t *testing.T) {
	if recallDirty("/nonexistent/.git") != nil {
		t.Fatal("a work tree never read must not invent a value")
	}
}
