package collectors

import "context"

// ActionsCollector advertises whether this agent is willing to run dashboard-
// dispatched commands (i.e. the executor is running and not locally hard-killed).
// It never executes anything. Actual enablement is gated server-side by the
// agent's `actions_enabled` flag — this only tells the dashboard the agent is
// new enough to support actions.
//
// `shell` tells the dashboard whether this box allows live terminal sessions
// (OPSERVO_ENABLE_SHELL=true and actions not hard-disabled) and, only then,
// which login users a session may run as.
type ActionsCollector struct {
	available bool
	shell     bool
	users     func() []string
}

func NewActionsCollector(available, shell bool, users func() []string) *ActionsCollector {
	return &ActionsCollector{available: available, shell: shell, users: users}
}
func (a *ActionsCollector) Name() string { return "actions" }

func (a *ActionsCollector) Collect(_ context.Context) (interface{}, error) {
	sh := map[string]interface{}{"enabled": a.shell}
	if a.shell && a.users != nil {
		sh["users"] = a.users()
	}
	return map[string]interface{}{"available": a.available, "shell": sh}, nil
}
