package collectors

import (
	"testing"
	"time"
)

func TestSudoersFileHasUnscopedNopasswd(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		data     string
		want     bool
	}{
		{
			name:     "no NOPASSWD",
			fileName: "sudoers",
			data:     "root ALL=(ALL) ALL\n",
			want:     false,
		},
		{
			name:     "commented out doesn't count",
			fileName: "sudoers",
			data:     "# opservo ALL=(root) NOPASSWD: /bin/systemctl restart nginx\n",
			want:     false,
		},
		{
			name:     "blanket NOPASSWD:ALL in main sudoers is a finding",
			fileName: "sudoers",
			data:     "deploy ALL=(ALL) NOPASSWD: ALL\n",
			want:     true,
		},
		{
			name:     "scoped opservo-actions grant is sanctioned, not a finding",
			fileName: "opservo-actions",
			data:     "opservo ALL=(root) NOPASSWD: /bin/systemctl restart nginx\n",
			want:     false,
		},
		{
			name:     "multi-command scoped opservo-actions grant is sanctioned",
			fileName: "opservo-actions",
			data:     "opservo ALL=(root) NOPASSWD: /bin/systemctl restart nginx, /usr/bin/tail -n 200 /var/log/nginx/error.log\n",
			want:     false,
		},
		{
			name:     "opservo-actions widened to NOPASSWD:ALL is still a finding",
			fileName: "opservo-actions",
			data:     "opservo ALL=(root) NOPASSWD: ALL\n",
			want:     true,
		},
		{
			name:     "NOPASSWD in any other sudoers.d file is always a finding",
			fileName: "custom-drop-in",
			data:     "someuser ALL=(root) NOPASSWD: /bin/systemctl restart nginx\n",
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sudoersFileHasUnscopedNopasswd(tt.fileName, []byte(tt.data))
			if got != tt.want {
				t.Errorf("sudoersFileHasUnscopedNopasswd(%q, %q) = %v, want %v", tt.fileName, tt.data, got, tt.want)
			}
		})
	}
}

func TestSecurityScore(t *testing.T) {
	tests := []struct {
		name   string
		report SecurityReport
		want   int
	}{
		{
			name:   "clean host scores 100",
			report: SecurityReport{FirewallEnabled: true},
			want:   100,
		},
		{
			name:   "root login permitted costs 30",
			report: SecurityReport{FirewallEnabled: true, RootLoginPermitted: true},
			want:   70,
		},
		{
			name:   "firewall disabled costs 20",
			report: SecurityReport{FirewallEnabled: false},
			want:   80,
		},
		{
			name: "one exposed port costs 15",
			report: SecurityReport{
				FirewallEnabled: true,
				DangerousPorts:  []DangerousPort{{Port: 3306}},
			},
			want: 85,
		},
		{
			name: "exposed-port penalty caps at 30 (three+ ports)",
			report: SecurityReport{
				FirewallEnabled: true,
				DangerousPorts:  []DangerousPort{{Port: 3306}, {Port: 6379}, {Port: 5432}, {Port: 27017}},
			},
			want: 70, // 4*15=60 capped to 30
		},
		{
			name: "suspicious process costs 25",
			report: SecurityReport{
				FirewallEnabled:     true,
				SuspiciousProcesses: []SuspiciousProcess{{Name: "xmrig"}},
			},
			want: 75,
		},
		{
			name:   "failed ssh over 50 costs 10",
			report: SecurityReport{FirewallEnabled: true, FailedSSH: FailedSSH{CountLastHour: 51}},
			want:   90,
		},
		{
			name:   "exactly 50 failed ssh is not penalized",
			report: SecurityReport{FirewallEnabled: true, FailedSSH: FailedSSH{CountLastHour: 50}},
			want:   100,
		},
		{
			name: "score never goes below zero",
			report: SecurityReport{
				FirewallEnabled:     false,
				RootLoginPermitted:  true,
				DangerousPorts:      []DangerousPort{{Port: 3306}, {Port: 6379}, {Port: 5432}},
				SuspiciousProcesses: []SuspiciousProcess{{Name: "xmrig"}},
				FailedSSH:           FailedSSH{CountLastHour: 999},
			},
			want: 0, // 100 -30 -20 -30 -25 -10 = -15 -> clamped to 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.report
			if got := securityScore(&r); got != tt.want {
				t.Errorf("securityScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTopSources(t *testing.T) {
	byIP := map[string]int{
		"1.1.1.1": 10,
		"2.2.2.2": 50,
		"3.3.3.3": 5,
		"4.4.4.4": 50,
		"5.5.5.5": 1,
		"6.6.6.6": 1,
	}
	got := topSources(byIP, 5)
	if len(got) != 5 {
		t.Fatalf("expected 5 sources, got %d", len(got))
	}
	// Highest count first; ties broken by the RAW IP ascending. Returned IPs are
	// privacy-masked to a /16 prefix (2.2.2.2 → 2.2.*.*).
	if got[0].IP != "2.2.*.*" || got[0].Count != 50 {
		t.Errorf("expected top source 2.2.*.* x50, got %s x%d", got[0].IP, got[0].Count)
	}
	if got[1].IP != "4.4.*.*" {
		t.Errorf("expected 4.4.*.* second (tie broken by raw IP), got %s", got[1].IP)
	}
}

func TestSuspicionReason(t *testing.T) {
	// actions/setup-go puts the real toolchain under the runner user's home.
	const goTool = "/home/ci/actions-runner/_work/_tool/go/1.26.9/x64/bin/go"
	const testBin = "/tmp/go-build436968702/b652/collectors.test"
	const testCmd = testBin + " -test.testlogfile=/tmp/go-build436968702/b652/testlog.txt"
	// goTest is a healthy `go test` child; mut tweaks one thing about it.
	goTest := func(mut func(*procFacts)) procFacts {
		pf := procFacts{PID: 96184, Name: "collectors.test", Exe: testBin, Cmdline: testCmd,
			ParentExe: goTool, ParentCmdline: "go test ./...", Age: 20 * time.Second}
		if mut != nil {
			mut(&pf)
		}
		return pf
	}
	tests := []struct {
		name        string
		f           procFacts
		wantFlagged bool
	}{
		{"known miner by name", procFacts{PID: 1234, Name: "xmrig", Exe: "/usr/bin/xmrig", Cmdline: "xmrig --donate 0", ParentExe: "/bin/bash"}, true},
		{"kdevtmpfsi miner", procFacts{PID: 4321, Name: "kdevtmpfsi"}, true},
		{"fake kthreadd", procFacts{PID: 9999, Name: "kthreadd"}, true},
		{"real kthreadd at pid 2 is fine", procFacts{PID: 2, Name: "kthreadd"}, false},
		{"real kdevtmpfs kernel thread is fine", procFacts{PID: 39, Name: "kdevtmpfs"}, false},
		{"binary from /tmp", procFacts{PID: 555, Name: "payload", Exe: "/tmp/payload", Cmdline: "/tmp/payload", ParentExe: "/bin/bash"}, true},
		{"dot-tmp executable", procFacts{PID: 556, Name: "x", Exe: "/opt/x.tmp", Cmdline: "/opt/x.tmp", ParentExe: "/bin/bash"}, true},
		{"benign nginx", procFacts{PID: 100, Name: "nginx", Exe: "/usr/sbin/nginx", Cmdline: "nginx: master process", ParentExe: "/sbin/init"}, false},

		// Go's own work directory, launched by the real toolchain.
		{"go test binary under go test", goTest(nil), false},
		{"go test under a -C invocation", goTest(func(f *procFacts) { f.ParentCmdline = "go -C agent test ./..." }), false},
		{"go run binary under go run", procFacts{PID: 777, Name: "main", Exe: "/tmp/go-build123/b001/exe/main", Cmdline: "/tmp/go-build123/b001/exe/main",
			ParentExe: "/usr/local/go/bin/go", ParentCmdline: "go run ./cmd/tool", Age: time.Minute}, false},
		{"go run binary under system go via /usr/bin", procFacts{PID: 777, Name: "main", Exe: "/tmp/go-build123/b001/exe/main",
			ParentExe: "/usr/lib/go-1.26/bin/go", ParentCmdline: "/usr/bin/go run main.go", Age: time.Minute}, false},

		// Same shape, but something is off → still flagged.
		{"spawned by a shell", goTest(func(f *procFacts) { f.ParentExe = "/bin/bash"; f.ParentCmdline = "bash" }), true},
		{"parent unknown (unreadable /proc/<ppid>/exe)", goTest(func(f *procFacts) { f.ParentExe = ""; f.ParentCmdline = "" }), true},
		{"re-parented to PID 1 after go exited", goTest(func(f *procFacts) { f.ParentExe = "/usr/lib/systemd/systemd"; f.ParentCmdline = "/sbin/init splash" }), true},
		{"parent named go in /tmp", goTest(func(f *procFacts) { f.ParentExe = "/tmp/x/go" }), true},
		{"parent named go in /dev/shm", goTest(func(f *procFacts) { f.ParentExe = "/dev/shm/go" }), true},
		{"parent go binary deleted", goTest(func(f *procFacts) { f.ParentExe = goTool + " (deleted)" }), true},
		{"parent go but not test/run", goTest(func(f *procFacts) { f.ParentCmdline = "go build ./..." }), true},
		{"parent go with no subcommand", goTest(func(f *procFacts) { f.ParentCmdline = "go" }), true},
		{"alive longer than the cap (go run miner.go)", goTest(func(f *procFacts) { f.ParentCmdline = "go run miner.go"; f.Age = 31 * time.Minute }), true},
		{"age unknown", goTest(func(f *procFacts) { f.Age = 0 }), true},
		{"dropper elsewhere inside a go-build dir", goTest(func(f *procFacts) { f.Exe = "/tmp/go-build1/payload"; f.Cmdline = "/tmp/go-build1/payload" }), true},
		{"miner named like a go test binary is still flagged by name", goTest(func(f *procFacts) { f.Name = "xmrig"; f.Exe = "/tmp/go-build1/b001/xmrig.test" }), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := suspicionReason(tt.f)
			if (got != "") != tt.wantFlagged {
				t.Errorf("suspicionReason() = %q, wantFlagged=%v", got, tt.wantFlagged)
			}
		})
	}
}

func TestGoSubcommand(t *testing.T) {
	cases := map[string]string{
		"go test ./...":                "test",
		"/usr/bin/go run main.go":      "run",
		"go -C agent test -race ./...": "test",
		"go -mod=mod build ./...":      "build",
		"go":                           "",
		"":                             "",
		"go -C":                        "",
	}
	for in, want := range cases {
		if got := goSubcommand(in); got != want {
			t.Errorf("goSubcommand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIptablesHasFiltering(t *testing.T) {
	dropPolicy := "Chain INPUT (policy DROP)\nnum  target  prot opt source  destination\n"
	if !iptablesHasFiltering(dropPolicy) {
		t.Error("expected default-deny INPUT policy to count as filtering")
	}
	acceptNoRules := "Chain INPUT (policy ACCEPT)\nnum  target  prot opt source  destination\n"
	if iptablesHasFiltering(acceptNoRules) {
		t.Error("expected accept-all INPUT with no rules to NOT count as filtering")
	}
	acceptWithDrop := "Chain INPUT (policy ACCEPT)\n1  DROP  tcp -- 1.2.3.4 0.0.0.0/0\n"
	if !iptablesHasFiltering(acceptWithDrop) {
		t.Error("expected a DROP rule to count as filtering")
	}
}

func TestParseLastOutput(t *testing.T) {
	out := "alice    pts/0   1.2.3.4   Tue Jun 24 10:00   still logged in\n" +
		"root     pts/1   10.0.0.5  Tue Jun 24 09:00 - 09:30  (00:30)\n" +
		"localadm tty1     :0        Tue Jun 24 08:00   still logged in\n" +
		"reboot   system boot  6.1.0  Tue Jun 24 07:00\n" +
		"\nwtmp begins Tue Jun 24 07:00\n"

	logins := parseLastOutput(out)
	if len(logins) != 3 {
		t.Fatalf("expected 3 logins (reboot/wtmp skipped), got %d: %+v", len(logins), logins)
	}
	// User + FromIP are privacy-masked (alice → al***, 1.2.3.4 → 1.2.*.*).
	if logins[0].User != "al***" || logins[0].FromIP != "1.2.*.*" {
		t.Errorf("unexpected first login: %+v", logins[0])
	}
	// Local tty login has no remote host.
	if logins[2].User != "lo******" || logins[2].FromIP != "" {
		t.Errorf("expected local login to have empty FromIP, got %+v", logins[2])
	}
}

// TestParseLastOutput_BusyBoxAlpine covers BusyBox's `last` (Alpine), which
// doesn't reliably support `-w` and lays out columns differently from GNU
// last, but renders the timestamp the same weekday/month/day/time way (per
// BusyBox's loginutils/last.c). Regression target: previously this format
// silently produced zero/garbage logins because the parser indexed fields
// positionally.
func TestParseLastOutput_BusyBoxAlpine(t *testing.T) {
	out := "root     pts/0    203.0.113.9     Wed Jul  1 09:15   still logged in\n" +
		"deploy   pts/1    198.51.100.2    Wed Jul  1 08:00 - 08:45  (00:45)\n" +
		"reboot   system boot                Wed Jul  1 07:00\n"

	logins := parseLastOutput(out)
	if len(logins) != 2 {
		t.Fatalf("expected 2 logins (reboot skipped), got %d: %+v", len(logins), logins)
	}
	if logins[0].User != "ro**" || logins[0].FromIP != "203.0.*.*" || logins[0].Timestamp != "Wed Jul  1 09:15" {
		t.Errorf("unexpected first busybox login: %+v", logins[0])
	}
	if logins[1].User != "de****" || logins[1].FromIP != "198.51.*.*" {
		t.Errorf("unexpected second busybox login: %+v", logins[1])
	}
}

// TestParseLastOutput_RHELWide covers a RHEL/CentOS-style `last -w` where the
// util-linux build appends seconds and a trailing year to the timestamp,
// which the fixed-field-count Debian/Ubuntu parsing previously mishandled.
func TestParseLastOutput_RHELWide(t *testing.T) {
	out := "opsuser  pts/2   10.20.30.40      Thu Jul  2 11:22:33 2026   still logged in\n" +
		"admin    pts/3   198.18.0.9       Thu Jul  2 10:00:00 2026 - 10:05:00 2026  (00:05)\n"

	logins := parseLastOutput(out)
	if len(logins) != 2 {
		t.Fatalf("expected 2 logins, got %d: %+v", len(logins), logins)
	}
	if logins[0].User != "op*****" || logins[0].FromIP != "10.20.*.*" || logins[0].Timestamp != "Thu Jul  2 11:22:33 2026" {
		t.Errorf("unexpected first RHEL login: %+v", logins[0])
	}
	if logins[1].User != "ad***" || logins[1].FromIP != "198.18.*.*" {
		t.Errorf("unexpected second RHEL login: %+v", logins[1])
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": true,
		"127.0.1.1": true,
		"::1":       true,
		"0.0.0.0":   false,
		"10.0.0.5":  false,
		"::":        false,
	}
	for ip, want := range cases {
		if got := isLoopbackAddr(ip); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", ip, got, want)
		}
	}
}
