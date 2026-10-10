package collectors

import (
	"reflect"
	"testing"
)

func TestParseIptablesBlockedPorts(t *testing.T) {
	// Shape of `iptables -S` on a ufw box after `ufw deny 8888` plus the rules
	// Opservo's AI added for an exposed Vite server (cmd 2b60c651).
	out := `-P INPUT DROP
-P FORWARD DROP
-N ufw-user-input
-A INPUT -j ufw-before-input
-A INPUT ! -i lo -p tcp -m tcp --dport 5173 -j DROP
-A INPUT ! -i lo -p tcp -m tcp --dport 5174 -j DROP
-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 6006 -j DROP
-A INPUT -p tcp -m tcp --dport 3000 -m conntrack --ctstate NEW -j DROP
-A INPUT -i eth1 -p tcp -m tcp --dport 4200 -j DROP
-A INPUT -p udp -m udp --dport 5353 -j DROP
-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT
-A ufw-user-input -p tcp -m tcp --dport 8888 -m comment --comment "'dapp_jupyter'" -j DROP
-A ufw-user-input -p tcp -m multiport --dports 9000:9002,9100 -j REJECT --reject-with tcp-reset
-A ufw-user-input -p tcp -m tcp --dport 7000 -j DROP
-A ufw-user-input -p tcp -m tcp --dport 7000 -j ACCEPT
-A DOCKER-USER -p tcp -m tcp --dport 8080 -j DROP
`
	b, a := parseIptablesBlockedPorts(out)
	got := finalizeBlocked(b, a)
	want := []int{5173, 5174, 8888, 9000, 9001, 9002, 9100}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("blocked = %v, want %v", got, want)
	}
	// Partial rules (source/state/interface-specific), UDP, FORWARD-side chains
	// and a port that is also ACCEPTed are never reported as blocked.
	for _, p := range []int{6006, 3000, 4200, 5353, 8080, 7000, 22} {
		for _, g := range got {
			if g == p {
				t.Fatalf("port %d must not be reported as blocked", p)
			}
		}
	}
}

func TestParseNftBlockedPorts(t *testing.T) {
	out := `table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "lo" accept
		ct state established,related accept
		iifname != "lo" tcp dport 5173 drop
		tcp dport { 5174, 6000-6002 } counter packets 0 bytes 0 reject with tcp reset
		ip saddr 192.168.1.0/24 tcp dport 3000 drop
		tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		tcp dport 8080 drop
	}
}
`
	b, a := parseNftBlockedPorts(out)
	got := finalizeBlocked(b, a)
	want := []int{5173, 5174, 6000, 6001, 6002}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("blocked = %v, want %v", got, want)
	}
}

func TestExpandPortSpec(t *testing.T) {
	if got := expandPortSpec("80,443,5173:5175", ",", ":"); !reflect.DeepEqual(got, []int{80, 443, 5173, 5174, 5175}) {
		t.Fatalf("got %v", got)
	}
	// Malformed, out-of-range and absurdly wide ranges are dropped, not guessed.
	if got := expandPortSpec("x,0,70000,1:65535", ",", ":"); len(got) != 0 {
		t.Fatalf("got %v, want nothing", got)
	}
}
