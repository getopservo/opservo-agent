package collectors

import (
	"path/filepath"
	"testing"
)

func TestRootlessSocketCandidates(t *testing.T) {
	got := rootlessSocketCandidates(1001, "/home/alice")
	want := []string{"/run/user/1001/docker.sock", "/home/alice/.docker/run/docker.sock"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d = %q, want %q", i, got[i], want[i])
		}
	}
	if got := rootlessSocketCandidates(1002, ""); len(got) != 1 {
		t.Errorf("no home → runtime dir only, got %v", got)
	}
}

func TestFindRootlessDockerDaemonsSkipFlag(t *testing.T) {
	t.Setenv(rootlessSkipEnv, "true")
	if got := findRootlessDockerDaemons(); got != nil {
		t.Errorf("%s=true must disable discovery, got %v", rootlessSkipEnv, got)
	}
}

func TestParseRootlessDaemonsRoundTrip(t *testing.T) {
	got := parseRootlessDaemons("1001\t1001\talice\t/home/alice\t/run/user/1001/docker.sock\nbad line\n")
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	d := got[0]
	if d.UID != 1001 || d.GID != 1001 || d.User != "alice" || d.Home != "/home/alice" || d.Socket != "/run/user/1001/docker.sock" {
		t.Errorf("got %+v", d)
	}
	env := d.env()
	if env[0] != "DOCKER_HOST=unix:///run/user/1001/docker.sock" || env[1] != "HOME=/home/alice" {
		t.Errorf("env = %v", env)
	}
	for _, e := range env {
		if len(e) > 0 && e[:5] != "PATH=" && e[:5] != "HOME=" && e[:12] != "DOCKER_HOST=" && e[:16] != "XDG_RUNTIME_DIR=" {
			t.Errorf("unexpected env %q (the agent's own environment must not leak)", e)
		}
	}
	if d.cred() == nil {
		t.Error("a non-root owner must get a credential drop")
	}
	if c := d.cred(); c.Uid != 1001 || c.Gid != 1001 {
		t.Errorf("cred = %+v", c)
	}
}

func TestParseDockerPSJSONAndHelpers(t *testing.T) {
	out := []byte(`{"ID":"abc","Names":"web","Image":"nginx:1.27","State":"running","Status":"Up 2 days"}
{"ID":"def","Names":"worker","Image":"app:1","State":"","Status":"Up 1 hour"}
not json
`)
	services, ids := parseDockerPSJSON(out)
	if len(services) != 2 || len(ids) != 2 || ids[1] != "def" {
		t.Fatalf("services=%+v ids=%v", services, ids)
	}
	if services[1].Status != "running" || services[0].Description != "nginx:1.27" || services[0].Type != "docker" {
		t.Errorf("got %+v", services)
	}
	applyRestartCounts(services, parseRestartCounts([]byte("/web|3\n/worker|0\n")))
	if services[0].RestartCount != 3 {
		t.Errorf("restart count not applied: %+v", services[0])
	}
	applyContainerStats(services, parseDockerStatsBrief([]byte("web\t12.5%\t100MiB / 1GiB\t10%\t1kB / 2kB\n")))
	if services[0].CPUPercent != 12.5 || services[0].MemoryBytes != 100*1024*1024 {
		t.Errorf("stats not applied: %+v", services[0])
	}
	if refs := parseContainerRefs("web\tnginx:1.27\n\nworker\tapp:1\n"); len(refs) != 2 || refs[1].Image != "app:1" {
		t.Errorf("refs = %+v", refs)
	}
	_ = filepath.Join
}
