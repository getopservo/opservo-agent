package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
	"strings"
)

// AgentInfo reports the agent's own build so the dashboard can flag servers
// running an out-of-date agent: the API compares BuildSHA to the sha256 in the
// manifest it currently serves for this arch.
type AgentInfo struct {
	Version   string `json:"version"`
	BuildSHA  string `json:"build_sha"` // sha256 of the running binary
	Arch      string `json:"arch"`      // amd64 / arm64
	OS        string `json:"os"`
	MachineID string `json:"machine_id,omitempty"` // stable per-host id (dedup double-installs)
}

type AgentInfoCollector struct {
	version   string
	sha       string
	arch      string
	machineID string
}

// NewAgentInfoCollector hashes the running binary once at startup; after a
// self-update the agent re-execs, so a fresh process recomputes the new hash.
func NewAgentInfoCollector(version string) *AgentInfoCollector {
	c := &AgentInfoCollector{version: version, arch: runtime.GOARCH, machineID: MachineID()}
	if exe, err := os.Executable(); err == nil {
		c.sha = sha256OfFile(exe)
	}
	return c
}

func (a *AgentInfoCollector) Name() string { return "agent" }

func (a *AgentInfoCollector) Collect(_ context.Context) (interface{}, error) {
	return &AgentInfo{Version: a.version, BuildSHA: a.sha, Arch: a.arch, OS: runtime.GOOS, MachineID: a.machineID}, nil
}

// MachineID returns a stable identifier for THIS physical host, used to detect
// the same machine enrolled more than once. Prefers the systemd/D-Bus machine-id,
// falling back to the DMI product UUID (bare metal / cloud VMs). Empty if none.
func MachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id
			}
		}
	}
	if data, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return strings.ToLower(id)
		}
	}
	return ""
}

func sha256OfFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
