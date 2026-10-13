package executor

import "testing"

// Same cases as api/src/lib/agentSelfProtect.test.ts — keep them in step.
func TestTouchesAgentSwitches(t *testing.T) {
	refused := []string{
		`sudo sh -c 'grep -q "^OPSERVO_ENABLE_SHELL=" /etc/infrapilot/config && sed -i "s/^OPSERVO_ENABLE_SHELL=.*/OPSERVO_ENABLE_SHELL=true/" /etc/infrapilot/config'`,
		"echo 'OPSERVO_ENABLE_SHELL=true' | sudo tee -a /etc/infrapilot/config",
		"sudo cat /etc/infrapilot/config",
		"sudo vi /etc/opservo/config",
		"sudo systemctl edit infrapilot-agent",
		"sudo systemctl --runtime edit opservo-agent.service",
		"echo Environment=X | sudo tee /etc/systemd/system/infrapilot-agent.service.d/x.conf",
		"export INFRAPILOT_ENABLE_ACTIONS=true",
		"OPSERVO_ENABLE_PROBES=true",
		"/usr/local/bin/infrapilot-agent --enable-shell",
	}
	allowed := []string{
		"sudo systemctl restart infrapilot-agent",
		"systemctl status infrapilot-agent",
		"sudo systemctl edit nginx",
		`psql "$(sed -n '/^[^#]/{p;q}' /etc/infrapilot/pg.conf)"`,
		"journalctl -u infrapilot-agent -n 50",
		"df -h",
		"cat /etc/infrapilot/configs-backup.txt",
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
