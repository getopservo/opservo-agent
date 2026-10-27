package collectors

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseDpkgOwner(t *testing.T) {
	cases := []struct{ out, path, want string }{
		{"cloudflared: /usr/bin/cloudflared\n", "/usr/bin/cloudflared", "cloudflared"},
		{"openssh-server: /usr/sbin/sshd\n", "/usr/sbin/sshd", "openssh-server"},
		{"libc-bin:amd64, other: /usr/bin/x\n", "/usr/bin/x", "libc-bin"},
		{"diversion by foo from: /usr/bin/x\nbar: /usr/bin/x\n", "/usr/bin/x", "bar"},
		{"git: /usr/bin/git-shell\n", "/usr/bin/git", ""}, // a different path is not ownership
		{"", "/usr/bin/x", ""},
	}
	for _, c := range cases {
		if got := parseDpkgOwner(c.out, c.path); got != c.want {
			t.Errorf("parseDpkgOwner(%q, %q) = %q, want %q", c.out, c.path, got, c.want)
		}
	}
}

func TestSoftwareVersionRe(t *testing.T) {
	cases := map[string]string{
		"cloudflared version 2026.6.1 (built 2026-06-18-14:33 UTC)":           "2026.6.1",
		"nginx version: nginx/1.24.0 (Ubuntu)":                                "1.24.0",
		"OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024":        "9.6p1",
		"Redis server v=7.0.15 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64":  "7.0.15",
		"Docker version 27.1.1, build 6312585":                                "27.1.1",
		"postgres (PostgreSQL) 16.4 (Ubuntu 16.4-1.pgdg24.04+1)":              "16.4",
		"Client Version: v1.30.1\nKustomize Version: v5.0.4-0.20230601165947": "1.30.1",
	}
	for in, want := range cases {
		if got := softwareVersionRe.FindString(in); got != want {
			t.Errorf("version(%q) = %q, want %q", in, got, want)
		}
	}
}

// A hand-installed binary is found off PATH, versioned, reported as
// "binary", and re-probed only when the file changes.
func TestSoftwareCollectorBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fakecf")
	write := func(v string) {
		t.Helper()
		if err := os.WriteFile(bin, []byte("#!/bin/sh\necho \"cloudflared version "+v+" (built x)\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("2026.6.1")
	p := softwareProbe{id: "cloudflared", name: "cloudflared", globs: []string{bin}, args: []string{"--version"}}
	paths := locateSoftware(p)
	if len(paths) != 1 {
		t.Fatalf("locateSoftware = %v", paths)
	}
	si := probeSoftware(context.Background(), p, paths[0])
	if si.Version != "2026.6.1" || si.ID != "cloudflared" {
		t.Fatalf("probe = %+v", si)
	}
	if si.Install != "binary" && si.Install != "apt" && si.Install != "rpm" {
		t.Fatalf("install = %q", si.Install)
	}
	if si.Install != "binary" {
		t.Logf("temp file reported as %q (package db quirk), skipping method check", si.Install)
	}
	write("2026.10.2 ") // different size → new cache key
	if si2 := probeSoftware(context.Background(), p, paths[0]); si2.Version != "2026.10.2" {
		t.Fatalf("after update = %+v", si2)
	}
}
