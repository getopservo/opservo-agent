package collectors

import "context"

// ProbesCollector advertises whether this server has locally opted in to
// running agent-based uptime checks (private-network TCP probes) via
// --enable-probes / OPSERVO_ENABLE_PROBES=true. The dashboard only offers
// "check from this server" for agents advertising enabled=true, and the API
// only hands checks to them. It never probes anything itself.
type ProbesCollector struct {
	enabled bool
}

func NewProbesCollector(enabled bool) *ProbesCollector {
	return &ProbesCollector{enabled: enabled}
}
func (p *ProbesCollector) Name() string { return "probes" }

func (p *ProbesCollector) Collect(_ context.Context) (interface{}, error) {
	return map[string]bool{"enabled": p.enabled}, nil
}
