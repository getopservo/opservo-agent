package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseVhostDetails_ApacheReverseProxy(t *testing.T) {
	conf := `<VirtualHost *:80>
    ServerName redmine.example.com
    Redirect permanent / https://redmine.example.com/
</VirtualHost>
<VirtualHost *:443>
    ServerName redmine.example.com
    ProxyPass /.well-known !
    ProxyPass /cable ws://192.0.2.27:3000/cable
    ProxyPass / "http://admin:s3cret@192.0.2.27:3000/"
    ProxyPassReverse / http://192.0.2.27:3000/
</VirtualHost>`
	out := map[string]vhostDetail{}
	parseVhostDetails(out, apacheSyntax, conf)
	got := out["redmine.example.com"]
	if got.Upstream != "http://192.0.2.27:3000" {
		t.Fatalf("upstream = %q, want the / target with credentials stripped", got.Upstream)
	}
	if got.Root != "" {
		t.Fatalf("root = %q, want empty", got.Root)
	}
}

func TestParseVhostDetails_ApachePassenger(t *testing.T) {
	conf := `<VirtualHost *:443>
    ServerName pm.example.com
    DocumentRoot "/usr/share/redmine/public/"
    PassengerAppRoot /usr/share/redmine
</VirtualHost>`
	out := map[string]vhostDetail{}
	parseVhostDetails(out, apacheSyntax, conf)
	want := vhostDetail{Root: "/usr/share/redmine/public", AppRoot: "/usr/share/redmine"}
	if out["pm.example.com"] != want {
		t.Fatalf("got %+v, want %+v", out["pm.example.com"], want)
	}
}

func TestParseVhostDetails_NginxLocationRootWins(t *testing.T) {
	conf := `server {
    server_name app.example.com www.app.example.com;
    root /var/www/app/public;
    location /api/ { proxy_pass http://127.0.0.1:4000; }
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
    location /ws { proxy_pass http://127.0.0.1:5000; }
}
server {
    server_name _;
    proxy_pass http://127.0.0.1:9999;
}`
	out := map[string]vhostDetail{}
	parseVhostDetails(out, nginxSyntax, conf)
	for _, d := range []string{"app.example.com", "www.app.example.com"} {
		got := out[d]
		if got.Upstream != "http://127.0.0.1:3000" || got.Root != "/var/www/app/public" {
			t.Fatalf("%s: got %+v", d, got)
		}
	}
	if _, ok := out["_"]; ok {
		t.Fatal("placeholder server_name must not be recorded")
	}
}

func TestRedmineDetection(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "Gemfile"), "source 'https://rubygems.org'\ngem 'rails', '7.2.2'\n")
	mustWrite(t, filepath.Join(dir, "lib", "redmine", "version.rb"),
		"module Redmine\n  module VERSION\n    MAJOR = 6\n    MINOR = 0\n    TINY  = 4\n    BRANCH = 'stable'\n  end\nend\n")
	app, ok := detectApp(dir)
	if !ok || app.Framework != "redmine" || app.Version != "6.0.4" {
		t.Fatalf("got %+v ok=%v, want redmine 6.0.4", app, ok)
	}

	plain := t.TempDir()
	mustWrite(t, filepath.Join(plain, "Gemfile"), "gem \"rails\"\n")
	if app, _ := detectApp(plain); app.Framework != "rails" {
		t.Fatalf("plain Rails app detected as %q", app.Framework)
	}
}

func TestCandidateAppDirsFrom_ThreeLevelsSkipsDependencyTrees(t *testing.T) {
	base := t.TempDir()
	deep := filepath.Join(base, "html", "redmine_updates_python", "redmine_update")
	for _, d := range []string{
		deep,
		filepath.Join(deep, "too", "deep"),
		filepath.Join(base, "html", "node_modules", "left-pad"),
		filepath.Join(base, "html", ".git", "objects"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]bool{}
	for _, d := range candidateAppDirsFrom([]string{base}) {
		got[d] = true
	}
	if !got[deep] {
		t.Errorf("level-3 app dir %q not walked", deep)
	}
	for _, bad := range []string{
		filepath.Join(deep, "too"),
		filepath.Join(base, "html", "node_modules"),
		filepath.Join(base, "html", ".git"),
	} {
		if got[bad] {
			t.Errorf("%q should not be walked", bad)
		}
	}
}

func TestMergeCandidateDirs(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	got := mergeCandidateDirs([]string{a, "/", a + "/", filepath.Join(a, "missing")}, []string{b, a})
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("got %v, want [%s %s]", got, a, b)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
