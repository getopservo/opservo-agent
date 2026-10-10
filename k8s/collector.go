package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Collector implements collectors.Collector (Name/Collect) so the k8s agent
// reuses the ordinary registry + sender. It runs the sub-collectors with a
// shared pod list, each under recover() and a per-step timeout, and records
// per-step errors in Snapshot.Errors instead of failing the heartbeat.
type Collector struct {
	clients     *Clients
	clusterName string
	stepTimeout time.Duration
	now         func() time.Time
}

// New builds the collector. clusterName is what the dashboard shows (env
// OPSERVO_CLUSTER_NAME, defaulting to the API server host at startup).
func New(clients *Clients, clusterName string) *Collector {
	return &Collector{clients: clients, clusterName: clusterName, stepTimeout: 20 * time.Second, now: time.Now}
}

func (c *Collector) Name() string { return "kubernetes" }

// Collect assembles the snapshot. Never panics; never returns a partial-nil.
func (c *Collector) Collect(ctx context.Context) (interface{}, error) {
	now := c.now().UTC()
	snap := &Snapshot{CollectedAt: now, Nodes: []Node{}, Workloads: []Workload{}, Events: []Event{}, Errors: map[string]string{}}
	snap.Pods.Problems = []ProblemPod{}

	pods, err := c.step(ctx, "pods", func(ctx context.Context) (interface{}, error) { return listPods(ctx, c.clients) })
	if err != nil {
		snap.Errors["pods"] = err.Error()
	}
	pl, _ := pods.([]corev1.Pod)

	if v, err := c.step(ctx, "cluster", func(ctx context.Context) (interface{}, error) {
		cl, nodes, err := collectCluster(ctx, c.clients, pl, c.clusterName)
		return [2]interface{}{cl, nodes}, err
	}); err != nil {
		snap.Errors["cluster"] = err.Error()
		if pair, ok := v.([2]interface{}); ok {
			if cl, ok := pair[0].(Cluster); ok {
				snap.Cluster = cl
			}
		}
	} else if pair, ok := v.([2]interface{}); ok {
		snap.Cluster = pair[0].(Cluster)
		if nodes, ok := pair[1].([]Node); ok && nodes != nil {
			snap.Nodes = nodes
		}
	}
	if snap.Cluster.Name == "" {
		snap.Cluster.Name = c.clusterName
	}

	if v, err := c.step(ctx, "apiserver", func(ctx context.Context) (interface{}, error) { return collectAPIServer(ctx, c.clients) }); err != nil {
		snap.Errors["apiserver"] = err.Error()
	} else if a, ok := v.(*APIServer); ok {
		snap.APIServer = a
	}

	if v, err := c.step(ctx, "pod_status", func(ctx context.Context) (interface{}, error) { return collectPods(ctx, c.clients, pl, now), nil }); err != nil {
		snap.Errors["pod_status"] = err.Error()
	} else if ps, ok := v.(PodSummary); ok {
		snap.Pods = ps
	}

	if v, err := c.step(ctx, "workloads", func(ctx context.Context) (interface{}, error) {
		return collectWorkloads(ctx, c.clients, pl, snap.Pods.Problems)
	}); err != nil {
		snap.Errors["workloads"] = err.Error()
		if ws, ok := v.([]Workload); ok && ws != nil {
			snap.Workloads = ws
		}
	} else if ws, ok := v.([]Workload); ok && ws != nil {
		snap.Workloads = ws
	}

	if _, err := c.step(ctx, "resources", func(ctx context.Context) (interface{}, error) {
		return nil, collectResources(ctx, c.clients, snap.Workloads, pl)
	}); err != nil {
		snap.Errors["resources"] = err.Error()
	}

	if v, err := c.step(ctx, "events", func(ctx context.Context) (interface{}, error) { return collectEvents(ctx, c.clients, now) }); err != nil {
		snap.Errors["events"] = err.Error()
	} else if evs, ok := v.([]Event); ok && evs != nil {
		snap.Events = evs
	}

	if len(snap.Errors) == 0 {
		snap.Errors = nil
	}
	return snap, nil
}

// step runs one sub-collector with a timeout and panic recovery.
func (c *Collector) step(parent context.Context, name string, fn func(ctx context.Context) (interface{}, error)) (out interface{}, err error) {
	ctx, cancel := context.WithTimeout(parent, c.stepTimeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("k8s %s: panic: %v", name, r)
			slog.Warn("k8s sub-collector panicked", "step", name, "panic", r)
		}
	}()
	return fn(ctx)
}
