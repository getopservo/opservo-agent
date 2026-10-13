package executor

import "regexp"

// selfProtectPatterns match commands that would change this agent's own LOCAL
// switches (OPSERVO_ENABLE_SHELL / _ACTIONS / _PROBES), its config file or its
// systemd unit. Those switches must be set by someone on the box; if the
// command channel could flip them, the dashboard flag would be the only lock.
// The API refuses the same commands (api/src/lib/agentSelfProtect.ts) — keep
// the lists identical. A guard against the obvious path, not a sandbox.
var selfProtectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)/etc/(?:infrapilot|opservo)/config\b`),
	regexp.MustCompile(`(?i)/etc/systemd/system/(?:infrapilot|opservo)-agent`),
	regexp.MustCompile(`(?i)systemctl\s+(?:--?[\w-]+\s+)*edit\s+(?:--?[\w-]+\s+)*(?:infrapilot|opservo)-agent`),
	regexp.MustCompile(`(?i)ENABLE_(?:SHELL|ACTIONS|PROBES)\b`),
	regexp.MustCompile(`(?i)--?enable-(?:shell|actions|probes)\b`),
}

const selfProtectMessage = "refused: this command would change the Opservo agent's own settings on this server (config file, service unit or OPSERVO_ENABLE_* switches) — change them over SSH, not from the dashboard"

// touchesAgentSwitches reports whether a dispatched command must be refused.
func touchesAgentSwitches(command string) bool {
	for _, p := range selfProtectPatterns {
		if p.MatchString(command) {
			return true
		}
	}
	return false
}
