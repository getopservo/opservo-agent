package collectors

import "context"

// ActionsCollector advertises whether this agent is willing to run dashboard-
// dispatched commands (i.e. the executor is running and not locally hard-killed).
// It never executes anything. Actual enablement is gated server-side by the
// agent's `actions_enabled` flag — this only tells the dashboard the agent is
// new enough to support actions.
type ActionsCollector struct {
	available bool
}

func NewActionsCollector(available bool) *ActionsCollector {
	return &ActionsCollector{available: available}
}
func (a *ActionsCollector) Name() string { return "actions" }

func (a *ActionsCollector) Collect(_ context.Context) (interface{}, error) {
	return map[string]bool{"available": a.available}, nil
}
