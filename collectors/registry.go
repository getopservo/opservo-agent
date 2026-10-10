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

// Registry holds all registered collectors and runs them.
type Registry struct {
	collectors []Collector
}

// NewRegistry creates a registry with the provided collectors.
func NewRegistry(cs []Collector) *Registry {
	return &Registry{collectors: cs}
}

// CollectAll runs all collectors in parallel and assembles the payload.
// A collector failure is recorded in Errors but does not fail the whole payload.
func (r *Registry) CollectAll(ctx context.Context) (*Payload, error) {
	type result struct {
		name string
		data interface{}
		err  error
	}

	results := make(chan result, len(r.collectors))

	for _, c := range r.collectors {
		go func(col Collector) {
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
				data, err = col.Collect(ctx)
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

	for range r.collectors {
		r := <-results
		if r.err != nil {
			payload.Errors[r.name] = r.err.Error()
		} else {
			payload.Data[r.name] = r.data
		}
	}

	if len(payload.Errors) == len(r.collectors) {
		return nil, fmt.Errorf("all collectors failed")
	}

	return payload, nil
}
