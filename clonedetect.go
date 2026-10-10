package main

// AMI-clone detection. The installer records the machine's identity
// (collectors.InstanceIdentity(): EC2 instance-id → DMI asset tag →
// machine-id) as OPSERVO_MACHINE_ID in /etc/infrapilot/config. If a box is
// baked into an AMI and launched again — an Auto Scaling group, or a manual
// clone — the new instance boots with the ORIGINAL server's credentials but a
// DIFFERENT identity. Without this check every clone would report as the same
// server: interleaved heartbeats, a flapping hostname, meaningless alerts.
//
// On a detected clone the agent discards the inherited credentials and
// re-registers using the fleet enrollment key (OPSERVO_ENROLL_KEY, a
// multi-use fleet_… token) recorded by the installer, then rewrites the
// config so the new identity survives restarts. With no fleet key it can only
// warn and carry on — in production the API refuses tokenless registration.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// isClone reports whether the recorded and current identities are both known
// and disagree. Either side empty means "can't tell" — never a clone, so an
// unreadable IMDS or a pre-identity config can never trigger a re-register.
func isClone(recorded, current string) bool {
	return recorded != "" && current != "" && recorded != current
}

// rewriteConfigIdentity replaces the identity lines of an installer-written
// config (KEY=VALUE lines) with the new credentials, preserving everything
// else. Missing keys are appended, so configs from older installers upgrade
// in place. Legacy INFRAPILOT_AGENT_ID/SECRET_KEY lines are dropped — they
// would shadow the new identity on the next boot.
func rewriteConfigIdentity(content, agentID, secretKey, machineID string) string {
	replacements := map[string]string{
		"OPSERVO_AGENT_ID":   agentID,
		"OPSERVO_SECRET_KEY": secretKey,
		"OPSERVO_MACHINE_ID": machineID,
	}
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "INFRAPILOT_AGENT_ID=") || strings.HasPrefix(trimmed, "INFRAPILOT_SECRET_KEY=") {
			continue
		}
		replaced := false
		for key, val := range replacements {
			if strings.HasPrefix(trimmed, key+"=") {
				out = append(out, key+"="+val)
				seen[key] = true
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, line)
		}
	}
	// Trim a trailing blank line before appending so additions stay adjacent.
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	for _, key := range []string{"OPSERVO_AGENT_ID", "OPSERVO_SECRET_KEY", "OPSERVO_MACHINE_ID"} {
		if !seen[key] {
			out = append(out, key+"="+replacements[key])
		}
	}
	return strings.Join(out, "\n") + "\n"
}

// persistIdentity atomically rewrites the config file with the new identity.
// Best-effort by design: on failure the agent still runs with the new in-memory
// credentials; it just re-detects the clone and re-registers on next restart.
func persistIdentity(path, agentID, secretKey, machineID string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	updated := rewriteConfigIdentity(string(data), agentID, secretKey, machineID)
	tmp := filepath.Join(filepath.Dir(path), ".opservo-config.tmp")
	if err := os.WriteFile(tmp, []byte(updated), 0o600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}
