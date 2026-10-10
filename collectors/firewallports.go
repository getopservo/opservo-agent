package collectors

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Per-port firewall state for the security report (B2.7).
//
// SEC_DEVSERVER_001 tells the user to "bind the dev server to 127.0.0.1 OR
// firewall the port". The second fix used to be invisible: the rule only read
// the bind address. firewallBlockedPorts reports the TCP ports the host
// firewall drops/rejects UNCONDITIONALLY on input, so the API can accept that
// fix too.
//
// Read-only and deliberately conservative — a port is only reported when a
// rule drops/rejects it for every source:
//   - iptables (`iptables -S`, which also shows ufw's rules — ufw writes its
//     deny/reject rules into the ufw-user-input chain): rules in INPUT and in
//     ufw's *-input chains, matching only on protocol/port (and optionally
//     `! -i lo`). Any source/destination/interface/state/rate match makes the
//     rule partial and it is ignored. An unconditional ACCEPT for the same port
//     in those chains cancels the block (we can't be sure which wins).
//   - nftables (`nft list ruleset`): rules in chains hooked on input with a
//     `tcp dport … drop|reject` verdict and no saddr/iifname/ct match.
// Default-deny policies are NOT inferred (Docker-published ports bypass INPUT
// entirely), and IPv6 rules are not read. Each command uses the security
// collector's 5 s timeout; any failure just means "no ports known".

const maxExpandedPortRange = 1024

// firewallBlockedPorts returns the sorted TCP ports blocked for every source.
func firewallBlockedPorts(ctx context.Context) []int {
	blocked := map[int]bool{}
	accepted := map[int]bool{}
	if hasBinary("iptables") {
		if out, err := runCmdTimeout(ctx, securityCmdTimeout, "iptables", "-S"); err == nil {
			b, a := parseIptablesBlockedPorts(string(out))
			mergePorts(blocked, b)
			mergePorts(accepted, a)
		}
	}
	if hasBinary("nft") {
		if out, err := runCmdTimeout(ctx, securityCmdTimeout, "nft", "list", "ruleset"); err == nil {
			b, a := parseNftBlockedPorts(string(out))
			mergePorts(blocked, b)
			mergePorts(accepted, a)
		}
	}
	return finalizeBlocked(blocked, accepted)
}

func mergePorts(dst, src map[int]bool) {
	for p := range src {
		dst[p] = true
	}
}

func finalizeBlocked(blocked, accepted map[int]bool) []int {
	out := []int{}
	for p := range blocked {
		if !accepted[p] {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// iptablesInputChain reports whether rules in this chain filter incoming
// traffic to the host: INPUT itself and ufw's input chains.
func iptablesInputChain(chain string) bool {
	if chain == "INPUT" {
		return true
	}
	return strings.HasPrefix(chain, "ufw") && strings.HasSuffix(chain, "-input")
}

var iptablesCommentRe = regexp.MustCompile(`-m comment --comment ("[^"]*"|\S+)`)

// parseIptablesBlockedPorts parses `iptables -S` output into the ports dropped
// or rejected unconditionally, and the ports accepted unconditionally, in the
// input chains. Pure and tested.
func parseIptablesBlockedPorts(out string) (blocked, accepted map[int]bool) {
	blocked, accepted = map[int]bool{}, map[int]bool{}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(iptablesCommentRe.ReplaceAllString(raw, ""))
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "-A" || !iptablesInputChain(f[1]) {
			continue
		}
		var ports []int
		target := ""
		tcp, ok := false, true
		for i := 2; i < len(f) && ok; i++ {
			switch f[i] {
			case "-p":
				if i+1 < len(f) && f[i+1] == "tcp" {
					tcp = true
				} else {
					ok = false
				}
				i++
			case "-m":
				if i+1 < len(f) && (f[i+1] == "tcp" || f[i+1] == "multiport") {
					i++
				} else {
					ok = false // state/conntrack/recent/limit/set → partial rule
				}
			case "--dport", "--dports", "--destination-port", "--destination-ports":
				if i+1 >= len(f) {
					ok = false
					break
				}
				ports = append(ports, expandPortSpec(f[i+1], ",", ":")...)
				i++
			case "!":
				// Only "! -i lo" (everything except loopback) keeps it unconditional.
				if i+2 < len(f) && f[i+1] == "-i" && f[i+2] == "lo" {
					i += 2
				} else {
					ok = false
				}
			case "-j":
				if i+1 < len(f) {
					target = f[i+1]
				}
				i++
			case "--reject-with":
				i++
			default:
				ok = false // -s / -d / -i / anything else narrows the rule
			}
		}
		if !ok || !tcp || len(ports) == 0 {
			continue
		}
		switch target {
		case "DROP", "REJECT":
			for _, p := range ports {
				blocked[p] = true
			}
		case "ACCEPT":
			for _, p := range ports {
				accepted[p] = true
			}
		}
	}
	return blocked, accepted
}

var (
	nftChainRe   = regexp.MustCompile(`^\s*chain\s+\S+\s*\{`)
	nftDportRe   = regexp.MustCompile(`\btcp dport (\{[^}]*\}|[0-9]+(?:-[0-9]+)?)`)
	nftVerdictRe = regexp.MustCompile(`\b(drop|reject|accept)\b(?:\s+with\s+.*)?\s*(?:comment\s+"[^"]*")?\s*$`)
	nftPartialRe = regexp.MustCompile(`\b(saddr|daddr|ct state|ct status|limit rate|meter|iifname "|iif )`)
	nftLoOnlyRe  = regexp.MustCompile(`\biifname != "lo"\s*`)
)

// parseNftBlockedPorts parses `nft list ruleset` output the same way: tcp dport
// drop/reject rules (and accepts) in chains hooked on input. Pure and tested.
func parseNftBlockedPorts(out string) (blocked, accepted map[int]bool) {
	blocked, accepted = map[int]bool{}, map[int]bool{}
	inInput := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if nftChainRe.MatchString(raw) {
			inInput = false
			continue
		}
		if strings.HasPrefix(line, "type filter hook input") {
			inInput = true
			continue
		}
		if !inInput || line == "" || line == "}" {
			continue
		}
		rule := nftLoOnlyRe.ReplaceAllString(line, "")
		if nftPartialRe.MatchString(rule) {
			continue
		}
		dm := nftDportRe.FindStringSubmatch(rule)
		vm := nftVerdictRe.FindStringSubmatch(rule)
		if dm == nil || vm == nil {
			continue
		}
		spec := strings.Trim(dm[1], "{} ")
		ports := expandPortSpec(strings.ReplaceAll(spec, " ", ""), ",", "-")
		dst := blocked
		if vm[1] == "accept" {
			dst = accepted
		}
		for _, p := range ports {
			dst[p] = true
		}
	}
	return blocked, accepted
}

// expandPortSpec turns "80,443,5173:5175" (or "5173-5175" with rangeSep "-")
// into individual ports, ignoring anything malformed and capping huge ranges.
func expandPortSpec(spec, listSep, rangeSep string) []int {
	var out []int
	for _, part := range strings.Split(spec, listSep) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, rangeSep)
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 {
			continue
		}
		if !isRange {
			out = append(out, a)
			continue
		}
		b, err := strconv.Atoi(hi)
		if err != nil || b < a || b > 65535 || b-a > maxExpandedPortRange {
			continue
		}
		for p := a; p <= b; p++ {
			out = append(out, p)
		}
	}
	return out
}
