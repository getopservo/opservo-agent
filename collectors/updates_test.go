package collectors

import (
	"strconv"
	"testing"
)

func TestParseAptUpgradable(t *testing.T) {
	cases := []struct {
		name         string
		out          string
		wantPending  int
		wantSecurity int
	}{
		{
			name: "mixed updates + security suites",
			out: `Listing...
libssl3/jammy-updates,jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.10]
curl/jammy-security 7.81.0-1ubuntu1.15 amd64 [upgradable from: 7.81.0-1ubuntu1.10]
bash/jammy-updates 5.1-6ubuntu1.1 amd64 [upgradable from: 5.1-6ubuntu1]`,
			wantPending:  3,
			wantSecurity: 2,
		},
		{
			name:         "nothing upgradable (just the header)",
			out:          "Listing...",
			wantPending:  0,
			wantSecurity: 0,
		},
		{
			name:         "empty output (e.g. after a full upgrade)",
			out:          "",
			wantPending:  0,
			wantSecurity: 0,
		},
		{
			name: "debian-style security suite",
			out: `Listing...
openssl/bookworm-security 3.0.11-1~deb12u2 amd64 [upgradable from: 3.0.9-1]`,
			wantPending:  1,
			wantSecurity: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, s := parseAptUpgradable(tc.out)
			if p != tc.wantPending || s != tc.wantSecurity {
				t.Fatalf("parseAptUpgradable: got pending=%d security=%d, want pending=%d security=%d", p, s, tc.wantPending, tc.wantSecurity)
			}
		})
	}
}

func TestParseAptUpgradableDetail(t *testing.T) {
	out := `Listing...
libssl3/jammy-updates,jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.10]
linux-image-generic/jammy-security 5.15.0.118.118 amd64 [upgradable from: 5.15.0.117.117]
curl/jammy-security 7.81.0-1ubuntu1.15 amd64 [upgradable from: 7.81.0-1ubuntu1.10]
tzdata/jammy-security 2026b-0ubuntu0.22.04 all [upgradable from: 2026a-0ubuntu0.22.04]
bash/jammy-updates 5.1-6ubuntu1.1 amd64 [upgradable from: 5.1-6ubuntu1]`
	pending, security, sec := parseAptUpgradableDetail(out)
	if pending != 5 || security != 4 || len(sec) != 4 {
		t.Fatalf("pending=%d security=%d len(sec)=%d", pending, security, len(sec))
	}
	if sec[0].Name != "libssl3" || sec[0].From != "3.0.2-0ubuntu1.10" || sec[0].To != "3.0.2-0ubuntu1.15" {
		t.Errorf("libssl3 parsed wrong: %+v", sec[0])
	}
	info := &UpdatesInfo{}
	fillPatchDetail(info, sec)
	if !info.KernelUpdatePending {
		t.Error("kernel update not detected")
	}
	// Kernel first, then high-exposure (sorted), then the rest.
	want := []string{"linux-image-generic", "curl", "libssl3", "tzdata"}
	for i, w := range want {
		if info.SecurityPackages[i].Name != w {
			t.Errorf("order[%d] = %s, want %s (%+v)", i, info.SecurityPackages[i].Name, w, info.SecurityPackages)
		}
	}
	if len(info.HighExposurePending) != 2 || info.HighExposurePending[0] != "libssl3" || info.HighExposurePending[1] != "curl" {
		t.Errorf("high exposure list: %v", info.HighExposurePending)
	}
	if !info.SecurityPackages[0].Kernel || !info.SecurityPackages[1].HighExposure || info.SecurityPackages[3].HighExposure {
		t.Errorf("tags wrong: %+v", info.SecurityPackages)
	}
}

func TestPatchClassification(t *testing.T) {
	kernel := []string{"linux-image-5.15.0-118-generic", "linux-image-generic", "kernel-core", "linux-modules-extra-5.15.0-118-generic"}
	for _, k := range kernel {
		if !isKernelPackage(k) {
			t.Errorf("%s should be a kernel package", k)
		}
	}
	high := []string{"openssl", "libssl3", "openssh-server", "libc6", "sudo", "nginx", "apache2", "php8.2-fpm", "mysql-server-8.0", "postgresql-16", "redis-server", "curl", "glibc", "systemd", "docker-ce"}
	for _, h := range high {
		if !isHighExposure(h) {
			t.Errorf("%s should be high exposure", h)
		}
	}
	low := []string{"tzdata", "htop", "vim", "man-db", "libfoo-dev", "python3-six", "fonts-dejavu"}
	for _, l := range low {
		if isHighExposure(l) || isKernelPackage(l) {
			t.Errorf("%s should be plain", l)
		}
	}
}

func TestFillPatchDetailCap(t *testing.T) {
	var sec []PendingUpdate
	for i := 0; i < 80; i++ {
		sec = append(sec, PendingUpdate{Name: "pkg" + strconv.Itoa(i)})
	}
	sec = append(sec, PendingUpdate{Name: "openssl"})
	info := &UpdatesInfo{}
	fillPatchDetail(info, sec)
	if len(info.SecurityPackages) != maxSecurityPackages {
		t.Fatalf("cap: %d", len(info.SecurityPackages))
	}
	if info.SecurityPackages[0].Name != "openssl" {
		t.Errorf("high-exposure package should survive the cap first: %s", info.SecurityPackages[0].Name)
	}
}

func TestParseDnf(t *testing.T) {
	check := `
nginx.x86_64                 1:1.20.1-14.el9                 appstream
openssl.x86_64               1:3.0.7-28.el9                  baseos
kernel.x86_64                5.14.0-427.el9                  baseos
Obsoleting Packages
foo.x86_64                   1-2                             baseos
`
	if n := parseDnfCheckUpdate(check); n != 3 {
		t.Errorf("check-update count = %d, want 3", n)
	}
	info := `RHSA-2026:1234 Important/Sec. openssl-1:3.0.7-28.el9.x86_64
RHSA-2026:1235 Important/Sec. openssl-1:3.0.7-28.el9.x86_64
RHSA-2026:2000 Moderate/Sec.  kernel-5.14.0-427.el9.x86_64
RHBA-2026:3000 bugfix         nginx-1:1.20.1-14.el9.x86_64`
	sec := parseDnfUpdateinfo(info)
	if len(sec) != 2 || sec[0].Name != "openssl" || sec[0].To != "1:3.0.7-28.el9" || sec[1].Name != "kernel" {
		t.Errorf("updateinfo parsed wrong: %+v", sec)
	}
	u := &UpdatesInfo{}
	fillPatchDetail(u, sec)
	if !u.KernelUpdatePending || len(u.HighExposurePending) != 1 {
		t.Errorf("dnf detail: %+v", u)
	}
}
