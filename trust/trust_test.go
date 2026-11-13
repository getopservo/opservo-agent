package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func mustList(t *testing.T, cidrs ...string) List {
	t.Helper()
	p, err := Parse(cidrs)
	if err != nil {
		t.Fatalf("Parse(%v): %v", cidrs, err)
	}
	return NewList(p, Hash(cidrs))
}

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		wantErr bool
	}{
		{"office LAN", []string{"192.168.1.0/24"}, false},
		{"bare IPv4 = /32", []string{"203.0.113.7"}, false},
		{"bare IPv6 = /128", []string{"2001:db8::1"}, false},
		{"IPv4 /16 is the widest allowed", []string{"10.1.0.0/16"}, false},
		{"IPv6 /32 is the widest allowed", []string{"2001:db8::/32"}, false},
		{"IPv4 /15 too wide", []string{"10.0.0.0/15"}, true},
		{"IPv4 any", []string{"0.0.0.0/0"}, true},
		{"IPv6 any", []string{"::/0"}, true},
		{"IPv6 /31 too wide", []string{"2001:db8::/31"}, true},
		{"garbage", []string{"office"}, true},
		{"masked agent form never parses", []string{"192.168.*.*"}, true},
		{"one bad entry rejects the list", []string{"192.168.1.0/24", "nope"}, true},
		{"zone not allowed", []string{"fe80::1%eth0"}, true},
		{"empty list", []string{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Parse(%v) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
		})
	}
	big := make([]string, MaxEntries+1)
	for i := range big {
		big[i] = "192.168.1.1"
	}
	if _, err := Parse(big); err == nil {
		t.Fatal("more than MaxEntries must be refused")
	}
}

func TestContains(t *testing.T) {
	l := mustList(t, "192.168.1.0/24", "203.0.113.7/32", "2001:db8:1::/48")
	cases := []struct {
		host string
		want bool
	}{
		{"192.168.1.50", true},
		{"192.168.1.255", true},
		{"192.168.2.50", false}, // same /16 as the LAN: a masked /16 must NOT trust it
		{"203.0.113.7", true},
		{"203.0.113.8", false},
		{"::ffff:192.168.1.9", true}, // IPv4-mapped form from some sshd builds
		{"2001:db8:1::abcd", true},
		{"[2001:db8:1::abcd]", true},
		{"2001:db8:2::1", false},
		{"192.168.*.*", false}, // masked form is never an address
		{"office-pc.lan", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := l.Contains(tc.host); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
	if (List{}).Contains("192.168.1.1") {
		t.Error("empty list must trust nothing")
	}
}

func TestStoreApplySignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)
	cidrs := []string{"192.168.1.0/24"}
	sign := func(agentID string, c []string) string {
		return hex.EncodeToString(ed25519.Sign(priv, []byte(SigningMessage(agentID, c))))
	}

	s := NewStore()
	if err := s.Apply(pubHex, "agent-1", Delivery{CIDRs: cidrs, Sig: sign("agent-1", cidrs)}); err != nil {
		t.Fatalf("valid list refused: %v", err)
	}
	if !s.Current().Contains("192.168.1.10") || s.Current().Hash() != Hash(cidrs) {
		t.Fatal("valid list not installed")
	}

	// Signed for another agent → refused, and the stored list is cleared.
	if err := s.Apply(pubHex, "agent-1", Delivery{CIDRs: cidrs, Sig: sign("agent-2", cidrs)}); err == nil {
		t.Fatal("signature for another agent accepted")
	}
	if !s.Current().Empty() {
		t.Fatal("refused list must clear the store")
	}

	// Tampered list (signature over a different list) → refused.
	wider := []string{"192.168.0.0/16"}
	if err := s.Apply(pubHex, "agent-1", Delivery{CIDRs: wider, Sig: sign("agent-1", cidrs)}); err == nil {
		t.Fatal("tampered list accepted")
	}
	// Unsigned → refused when a key is embedded.
	if err := s.Apply(pubHex, "agent-1", Delivery{CIDRs: cidrs}); err == nil {
		t.Fatal("unsigned list accepted with a key embedded")
	}
	// No embedded key (dev build) → accepted unsigned.
	if err := s.Apply("", "agent-1", Delivery{CIDRs: cidrs}); err != nil {
		t.Fatalf("dev build refused unsigned list: %v", err)
	}
	// Signed but too wide → refused.
	anyNet := []string{"0.0.0.0/0"}
	if err := s.Apply(pubHex, "agent-1", Delivery{CIDRs: anyNet, Sig: sign("agent-1", anyNet)}); err == nil || !s.Current().Empty() {
		t.Fatal("0.0.0.0/0 accepted")
	}
	// Empty signed list switches the feature off.
	if err := s.Apply(pubHex, "agent-1", Delivery{CIDRs: []string{}, Sig: sign("agent-1", []string{})}); err != nil || !s.Current().Empty() {
		t.Fatalf("empty list: err=%v empty=%v", err, s.Current().Empty())
	}
	var nilStore *Store
	if !nilStore.Current().Empty() {
		t.Fatal("nil store must be empty")
	}
}

// The signing message and hash are a contract with the API
// (api/src/lib/officeAddresses.ts) — pin them.
func TestWireContract(t *testing.T) {
	if got := SigningMessage("a1", []string{"192.168.1.0/24", "203.0.113.7/32"}); got != "trusted-networks\na1\n192.168.1.0/24\n203.0.113.7/32" {
		t.Fatalf("SigningMessage = %q", got)
	}
	// sha256("192.168.1.0/24\n203.0.113.7/32")[:16 hex]
	if got := Hash([]string{"192.168.1.0/24", "203.0.113.7/32"}); got != "6b37c14274aeb0bc" {
		t.Fatalf("Hash = %s", got)
	}
	// A signature made by the API (api/src/lib/commandSigning.test.ts, the
	// test-only seed shared with shell_test.go) verifies here.
	const testPub = "1d53ae157ea41fc42412ffa3d865cce96cd1b57441bdde097c91f00dea5b217e"
	apiSig := "95cf4a53f2a769cc6f833763adb51569003b646b48f4f40035015187dc35012868c7b194db94d7533edb6d46c2b54e456e24f28a261fb40bb023baf312568d07"
	d := Delivery{CIDRs: []string{"192.168.1.0/24", "203.0.113.7/32"}, Sig: apiSig}
	if err := VerifySignature(testPub, "agent-1", d); err != nil {
		t.Fatalf("API signature refused: %v", err)
	}
	if err := VerifySignature(testPub, "agent-2", d); err == nil {
		t.Fatal("API signature accepted for another agent")
	}
}
