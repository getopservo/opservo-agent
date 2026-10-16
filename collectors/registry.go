package collectors

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Collector is the interface every data collector must implement.
// Each collector is responsible for one category of system data.
type Collector interface {
	// Name returns the unique identifier for this collector (used as JSON key)
	Name() string
	// Collect gathers data and returns it as a serializable struct.
	// Implementations must respect context cancellation.
	Collect(ctx context.Context) (interface{}, error)
}

// Payload is the full heartbeat payload sent to the API.
type Payload struct {
	CollectedAt time.Time              `json:"collected_at"`
	Data        map[string]interface{} `json:"data"`
	Errors      map[string]string      `json:"errors,omitempty"`
}

// DefaultCollectorTimeout bounds one collector's Collect call per heartbeat.
// A wedged probe (a hung `docker ps`, a journald that never answers) used to
// hold the whole heartbeat forever and take the server "offline" in the
// dashboard; now it is cancelled, recorded in Payload.Errors and the other
// collectors' data still ships on time.
const DefaultCollectorTimeout = 20 * time.Second

// Registry holds all registered collectors and runs them.
type Registry struct {
	collectors []Collector
	// PerCollectorTimeout is the deadline each collector gets per CollectAll.
	// Defaults to DefaultCollectorTimeout; tests shorten it.
	PerCollectorTimeout time.Duration
}

// NewRegistry creates a registry with the provided collectors.
func NewRegistry(cs []Collector) *Registry {
	return &Registry{collectors: cs, PerCollectorTimeout: DefaultCollectorTimeout}
}

// CollectAll runs all collectors in parallel and assembles the payload.
// A collector failure is recorded in Errors but does not fail the whole payload.
//
// Every collector runs under its own context deadline (PerCollectorTimeout).
// A collector that does not return by then is recorded as
// Errors[name] = "timed out after <d>" and CollectAll returns without it —
// its goroutine may keep running until its context cancellation lands, but it
// can no longer delay the heartbeat.
func (r *Registry) CollectAll(ctx context.Context) (*Payload, error) {
	type result struct {
		name string
		data interface{}
		err  error
	}

	timeout := r.PerCollectorTimeout
	if timeout <= 0 {
		timeout = DefaultCollectorTimeout
	}

	// Buffered to len(collectors) so a straggler that finishes after we have
	// stopped listening can still send and exit instead of leaking forever.
	results := make(chan result, len(r.collectors))

	for _, c := range r.collectors {
		go func(col Collector) {
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			start := time.Now()
			// Recover a panicking collector into an error, so one bad probe can
			// never crash the whole agent (which would take the server offline).
			var data interface{}
			var err error
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						err = fmt.Errorf("collector %q panicked: %v", col.Name(), rec)
					}
				}()
				data, err = col.Collect(cctx)
			}()
			elapsed := time.Since(start)
			if err != nil {
				slog.Warn("Collector error", "collector", col.Name(), "duration", elapsed, "error", err)
			} else {
				slog.Debug("Collector success", "collector", col.Name(), "duration", elapsed)
			}
			results <- result{name: col.Name(), data: data, err: err}
		}(c)
	}

	payload := &Payload{
		CollectedAt: time.Now().UTC(),
		Data:        make(map[string]interface{}),
		Errors:      make(map[string]string),
	}

	// Wait for every collector, but never past the per-collector deadline
	// (plus a small grace so a collector that honours its context and returns
	// ctx.Err() right at the deadline is still attributed its own error).
	deadline := time.NewTimer(timeout + 500*time.Millisecond)
	defer deadline.Stop()
	reported := make(map[string]bool, len(r.collectors))
	pending := len(r.collectors)
collect:
	for pending > 0 {
		select {
		case res := <-results:
			pending--
			reported[res.name] = true
			if res.err != nil {
				payload.Errors[res.name] = res.err.Error()
			} else {
				payload.Data[res.name] = res.data
			}
		case <-deadline.C:
			break collect
		}
	}
	if pending > 0 {
		for _, c := range r.collectors {
			if !reported[c.Name()] {
				payload.Errors[c.Name()] = fmt.Sprintf("timed out after %s", timeout)
				slog.Warn("Collector timed out", "collector", c.Name(), "timeout", timeout)
			}
		}
	}

	if len(payload.Errors) == len(r.collectors) {
		return nil, fmt.Errorf("all collectors failed")
	}

	return payload, nil
}
