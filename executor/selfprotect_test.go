package executor

import "testing"

// Same cases as api/src/lib/agentSelfProtect.test.ts — keep them in step.
func TestTouchesAgentSwitches(t *testing.T) {
	refused := []string{
		`sudo sh -c 'grep -q "^OPSERVO_ENABLE_SHELL=" /etc/opservo/config && sed -i "s/^OPSERVO_ENABLE_SHELL=.*/OPSERVO_ENABLE_SHELL=true/" /etc/opservo/config'`,
		"echo 'OPSERVO_ENABLE_SHELL=true' | sudo tee -a /etc/opservo/config",
		"sudo cat /etc/opservo/config",
		"sudo vi /etc/opservo/config",
		"sudo systemctl edit opservo-agent",
		"sudo systemctl --runtime edit opservo-agent.service",
		"echo Environment=X | sudo tee /etc/systemd/system/opservo-agent.service.d/x.conf",
		"export OPSERVO_ENABLE_ACTIONS=true",
		"OPSERVO_ENABLE_PROBES=true",
		"/usr/local/bin/opservo-agent --enable-shell",
	}
	allowed := []string{
		"sudo systemctl restart opservo-agent",
		"systemctl status opservo-agent",
		"sudo systemctl edit nginx",
		`psql "$(sed -n '/^[^#]/{p;q}' /etc/opservo/pg.conf)"`,
		"journalctl -u opservo-agent -n 50",
		"df -h",
		"cat /etc/opservo/configs-backup.txt",
	}
	for _, c := range refused {
		if !touchesAgentSwitches(c) {
			t.Errorf("expected refusal: %s", c)
		}
	}
	for _, c := range allowed {
		if touchesAgentSwitches(c) {
			t.Errorf("expected allowed: %s", c)
		}
	}
}
