// Package trust holds the workspace's "office addresses" — the CIDR list an
// owner/admin marks as trusted in the dashboard (12 Nov 2026). The agent uses
// it ONLY to label SSH logins on this box as coming from a trusted address,
// so the API can tell "a few failed `sudo -n` right after an office login"
// apart from someone poking at sudo from elsewhere. It never grants access to
// anything and changes nothing on the box.
//
// Trust model:
//   - the list arrives in the heartbeat RESPONSE, Ed25519-signed by the API
//     with the same keypair as commands and probes, domain-tagged
//     "trusted-networks" (a command message starts with a UUID, a probe with
//     "probe", a cancel with "cancel"), so a forged response or a DB write
//     can't make this box call an attacker's address trusted;
//   - when the embedded public key is set, an unsigned or badly signed list is
//     REFUSED and the stored list is cleared (fail closed: nothing trusted);
//   - matching uses the FULL source address on the box, before maskIP() — a
//     masked /16 is never a trust basis;
//   - the agent reports the hash of the list it used, and the API ignores the
//     verdict unless that hash matches the workspace's current list.
package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// MaxEntries mirrors the API-side cap on office addresses.
const MaxEntries = 32

// Narrowest-allowed widths: an IPv4 entry may not be wider than a /16, an IPv6
// entry not wider than a /32 (same rule as the API). Enforced here too so a
// tampered list can't trust the whole internet.
const (
	minPrefixV4 = 16
	minPrefixV6 = 32
)

// Delivery is the `trusted_networks` object of a heartbeat response.
type Delivery struct {
	CIDRs []string `json:"cidrs"`
	Sig   string   `json:"sig"` // hex Ed25519, "" when API signing is off
}

// SigningMessage must match the API's trustedNetworksSigningMessage
// byte-for-byte.
func SigningMessage(agentID string, cidrs []string) string {
	return "trusted-networks\n" + agentID + "\n" + strings.Join(cidrs, "\n")
}

// Hash identifies a list exactly as delivered (order included — the API sends
// its stored, sorted list). Must match the API's officeAddressesHash.
func Hash(cidrs []string) string {
	sum := sha256.Sum256([]byte(strings.Join(cidrs, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// Parse turns a delivered list into prefixes, rejecting the whole list if any
// entry is malformed or too wide.
func Parse(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) > MaxEntries {
		return nil, fmt.Errorf("too many entries (%d > %d)", len(cidrs), MaxEntries)
	}
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		var p netip.Prefix
		if strings.Contains(c, "/") {
			pp, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("bad entry %q: %w", c, err)
			}
			p = pp
		} else {
			a, err := netip.ParseAddr(c)
			if err != nil {
				return nil, fmt.Errorf("bad entry %q: %w", c, err)
			}
			if a.Zone() != "" {
				return nil, fmt.Errorf("bad entry %q: zone not allowed", c)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !p.IsValid() {
			return nil, fmt.Errorf("bad entry %q", c)
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Addr().Is4() && p.Bits() < minPrefixV4 {
			return nil, fmt.Errorf("entry %q is wider than /%d", c, minPrefixV4)
		}
		if p.Addr().Is6() && p.Bits() < minPrefixV6 {
			return nil, fmt.Errorf("entry %q is wider than /%d", c, minPrefixV6)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// VerifySignature fails CLOSED on malformed input; no-op when pubKeyHex is
// empty (same convention as command and probe signing).
func VerifySignature(pubKeyHex, agentID string, d Delivery) error {
	if pubKeyHex == "" {
		return nil
	}
	pub, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad embedded signing public key")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(d.Sig))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("missing or malformed signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(SigningMessage(agentID, d.CIDRs)), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// List is an immutable view of the office addresses in force.
type List struct {
	prefixes []netip.Prefix
	hash     string
}

// NewList builds a List from already-parsed prefixes (tests and Store).
func NewList(prefixes []netip.Prefix, hash string) List {
	return List{prefixes: prefixes, hash: hash}
}

// Empty reports whether no office address is set (the feature is off).
func (l List) Empty() bool { return len(l.prefixes) == 0 }

// Hash is the hash of the delivered list (see Hash).
func (l List) Hash() string { return l.hash }

// Contains reports whether host — a FULL IP address as logged by sshd, `who`
// or `last` — falls inside an office address. Hostnames, masked addresses and
// anything else that is not a plain IP are never trusted.
func (l List) Contains(host string) bool {
	if len(l.prefixes) == 0 {
		return false
	}
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	if i := strings.IndexByte(h, '%'); i >= 0 { // IPv6 zone (fe80::1%eth0)
		h = h[:i]
	}
	a, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range l.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Store keeps the latest verified list between heartbeats. Safe for
// concurrent use (the collector reads it while the sender writes it).
type Store struct {
	mu   sync.RWMutex
	list List
}

func NewStore() *Store { return &Store{} }

// Current returns the list in force (empty when none, or when the last
// delivery was refused). A nil Store is an empty list.
func (s *Store) Current() List {
	if s == nil {
		return List{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.list
}

// Apply verifies and installs a delivered list. On any failure the stored
// list is CLEARED (nothing is trusted) and the error is returned.
func (s *Store) Apply(pubKeyHex, agentID string, d Delivery) error {
	err := VerifySignature(pubKeyHex, agentID, d)
	var prefixes []netip.Prefix
	if err == nil {
		prefixes, err = Parse(d.CIDRs)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.list = List{}
		return err
	}
	if len(prefixes) == 0 {
		s.list = List{}
		return nil
	}
	s.list = NewList(prefixes, Hash(d.CIDRs))
	return nil
}
