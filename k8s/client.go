package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
)

// Clients bundles the API handles every sub-collector needs. Tests build one
// from fake clientsets; production uses NewInClusterClients.
type Clients struct {
	Core    kubernetes.Interface
	Metrics metricsclient.Interface // nil when metrics-server is not installed
	// RawMetrics fetches the API server's Prometheus text at /metrics. Nil when
	// the discovery REST client is unavailable (fake clientsets); the apiserver
	// sub-collector then reports "not available" rather than failing.
	RawMetrics func(ctx context.Context) ([]byte, error)
}

// NewInClusterClients builds clients from the pod's service account; falls back
// to $KUBECONFIG / ~/.kube/config for local development (`--dev`).
func NewInClusterClients() (*Clients, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kc := os.Getenv("KUBECONFIG")
		if kc == "" {
			if home, e := os.UserHomeDir(); e == nil {
				kc = filepath.Join(home, ".kube", "config")
			}
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kc)
		if err != nil {
			return nil, fmt.Errorf("k8s client: no in-cluster config and no kubeconfig: %w", err)
		}
	}
	cfg.Timeout = 20 * time.Second
	cfg.UserAgent = "opservo-k8s-agent"
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s client: core clientset: %w", err)
	}
	c := &Clients{Core: core}
	if m, err := metricsclient.NewForConfig(cfg); err == nil {
		c.Metrics = m
	}
	rc := core.Discovery().RESTClient()
	if rc != nil {
		c.RawMetrics = func(ctx context.Context) ([]byte, error) {
			return rc.Get().AbsPath("/metrics").Timeout(10 * time.Second).DoRaw(ctx)
		}
	}
	return c, nil
}
