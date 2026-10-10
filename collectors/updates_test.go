package collectors

import "testing"

func TestParseAptUpgradable(t *testing.T) {
	cases := []struct {
		name           string
		out            string
		wantPending    int
		wantSecurity   int
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
