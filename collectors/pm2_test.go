package collectors

import "testing"

func TestParsePM2DaemonTitle(t *testing.T) {
	cases := map[string]string{
		"PM2 v6.0.14: God Daemon (/home/softuvo/.pm2)":   "/home/softuvo/.pm2",
		"PM2 v5.3.0: God Daemon (/etc/.pm2)\x00\x00":     "/etc/.pm2",
		"PM2 v7.0.1: God Daemon (/root/.pm2/)":           "/root/.pm2",
		"node /usr/lib/node_modules/pm2/bin/pm2 jlist":   "",
		"PM2 v6.0.14: God Daemon (relative/not/allowed)": "",
	}
	for in, want := range cases {
		got, ok := parsePM2DaemonTitle(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q → %q,%v; want %q", in, got, ok, want)
		}
	}
}

func TestParseProcOwner(t *testing.T) {
	uid, gid, ok := parseProcOwner("Name:\tPM2 v6\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\n")
	if !ok || uid != 1000 || gid != 1001 {
		t.Fatalf("got %d %d %v", uid, gid, ok)
	}
	if _, _, ok := parseProcOwner("Name:\tx\n"); ok {
		t.Fatal("missing Uid/Gid must not be ok")
	}
}

func TestPM2CLICandidatesPreferNodeBin(t *testing.T) {
	c := pm2CLICandidates("/home/ubuntu/.nvm/versions/node/v20.11.0/bin/node", "/home/ubuntu")
	if c[0] != "/home/ubuntu/.nvm/versions/node/v20.11.0/bin/pm2" || c[1] != "/home/ubuntu/.npm-global/bin/pm2" {
		t.Fatalf("unexpected order: %v", c)
	}
}

func TestParsePM2JList(t *testing.T) {
	out := []byte(">>>> In-memory PM2 is out-of-date, do:\n>>>> $ pm2 update\n" +
		`[{"name":"api","pm2_env":{"status":"online","restart_time":3,"pm_err_log_path":"/home/u/.pm2/logs/api-error.log","pm_cwd":"/srv/api"},"monit":{"memory":1048576,"cpu":2.5}}]`)
	procs, err := parsePM2JList(out)
	if err != nil || len(procs) != 1 {
		t.Fatalf("err=%v procs=%v", err, procs)
	}
	p := procs[0]
	if p.Name != "api" || p.PM2.Status != "online" || p.PM2.Restarts != 3 || p.PM2.ErrLogPath != "/home/u/.pm2/logs/api-error.log" || p.PM2.Cwd != "/srv/api" || p.Monit.Memory != 1048576 {
		t.Fatalf("bad parse: %+v", p)
	}
}

func TestPM2AppFromLogName(t *testing.T) {
	cases := map[string]string{
		"api-error.log":      "api",
		"my-app-error-3.log": "my-app",
		"legacy.error.log":   "legacy",
		"api-out.log":        "",
		"error.log":          "",
	}
	for in, want := range cases {
		if got := pm2AppFromLogName(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}
