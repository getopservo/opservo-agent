// opservo-k8s-agent — the Kubernetes cluster collector.
//
// Runs as ONE replica per cluster (Deployment, read-only ClusterRole, non-root,
// no privileged pods). It registers with the same enrollment-token flow as the
// Linux agent and sends the same HMAC-signed heartbeat; the cluster shows up in
// the dashboard as a server of kind "kubernetes" with `data.kubernetes` in the
// snapshot. No remote command execution, no probes, no self-update: the image
// is upgraded by bumping the Deployment tag.
//
// Credentials: a pod restart must NOT re-register (enrollment tokens are
// single-use and re-registering would duplicate the cluster), so the agent id
// + secret are persisted into a Secret in its own namespace
// (opservo-agent-credentials) — the only write permission it holds.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/softuvo-ai/opservo-agent/collectors"
	"github.com/softuvo-ai/opservo-agent/k8s"
	"github.com/softuvo-ai/opservo-agent/sender"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

const credentialsSecret = "opservo-agent-credentials"

var (
	apiURL      = flag.String("api-url", envOr("OPSERVO_API_URL", "https://api.getopservo.com"), "Opservo API URL")
	enrollToken = flag.String("token", envOr("OPSERVO_TOKEN", ""), "Enrollment token (ipk_… single-use or fleet_… multi-use)")
	clusterName = flag.String("cluster-name", envOr("OPSERVO_CLUSTER_NAME", ""), "Name shown in the dashboard (default: API server host)")
	namespace   = flag.String("namespace", envOr("OPSERVO_NAMESPACE", envOr("POD_NAMESPACE", "opservo")), "Namespace holding the credentials Secret")
	interval    = flag.Duration("interval", 60*time.Second, "Heartbeat interval")
	devMode     = flag.Bool("dev", false, "Development mode (verbose logging, skip TLS verify, kubeconfig fallback)")
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	flag.Parse()
	level := slog.LevelInfo
	if *devMode {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
	slog.Info("Opservo Kubernetes agent starting", "version", version, "api_url", *apiURL, "interval", *interval)

	clients, err := k8s.NewInClusterClients()
	if err != nil {
		slog.Error("cannot talk to the Kubernetes API", "error", err)
		os.Exit(1)
	}
	name := *clusterName
	if name == "" {
		name = defaultClusterName()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	agentID, secret := loadCredentials(ctx, clients, *namespace)
	if agentID == "" || secret == "" {
		if *enrollToken == "" {
			slog.Error("no stored credentials and no OPSERVO_TOKEN — create the cluster in the dashboard (Add server → Kubernetes) and apply the manifest it gives you")
			os.Exit(1)
		}
		identity := clusterIdentity(ctx, clients)
		slog.Info("Registering cluster", "name", name, "identity", identity)
		id, key, err := sender.RegisterKind(*apiURL, version, *devMode, *enrollToken, identity, name, "kubernetes")
		if err != nil {
			slog.Error("registration failed", "error", err)
			os.Exit(1) // the Deployment restarts us; a bad/expired token keeps failing loudly
		}
		agentID, secret = id, key
		if err := saveCredentials(ctx, clients, *namespace, id, key); err != nil {
			slog.Warn("could not persist credentials to a Secret — a pod restart will re-register this cluster", "error", err)
		} else {
			slog.Info("Registered; credentials stored", "agent_id", id, "secret", credentialsSecret)
		}
	} else {
		slog.Info("Using stored credentials", "agent_id", agentID)
	}

	registry := collectors.NewRegistry([]collectors.Collector{
		k8s.New(clients, name),
		collectors.NewAgentInfoCollector(version),
	})
	s := sender.New(*apiURL, agentID, secret, *devMode)

	send := func() {
		payload, err := registry.CollectAll(ctx)
		if err != nil {
			slog.Error("collection failed", "error", err)
			return
		}
		payload.Data["kind"] = "kubernetes"
		body, err := json.Marshal(payload)
		if err != nil {
			slog.Error("marshal failed", "error", err)
			return
		}
		if _, err := s.SendRaw(ctx, body); err != nil {
			slog.Error("heartbeat send failed", "error", err)
			return
		}
		slog.Debug("heartbeat sent", "bytes", len(body))
	}

	send()
	t := time.NewTicker(*interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			send()
		case <-ctx.Done():
			slog.Info("shutting down")
			return
		}
	}
}

// clusterIdentity is the kube-system namespace UID — stable for the life of
// the cluster, and what the API dedups on (agents.machine_id).
func clusterIdentity(ctx context.Context, c *k8s.Clients) string {
	ns, err := c.Core.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		return ""
	}
	return "k8s-" + string(ns.UID)
}

// defaultClusterName derives a readable name from the in-cluster API host.
func defaultClusterName() string {
	if h := os.Getenv("KUBERNETES_SERVICE_HOST"); h != "" {
		return "k8s-" + strings.ReplaceAll(h, ".", "-")
	}
	if u, err := url.Parse(os.Getenv("KUBERNETES_MASTER")); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return "kubernetes"
}

func loadCredentials(ctx context.Context, c *k8s.Clients, ns string) (string, string) {
	sec, err := c.Core.CoreV1().Secrets(ns).Get(ctx, credentialsSecret, metav1.GetOptions{})
	if err != nil {
		return "", ""
	}
	return string(sec.Data["agent_id"]), string(sec.Data["secret_key"])
}

func saveCredentials(ctx context.Context, c *k8s.Clients, ns, id, key string) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: credentialsSecret, Namespace: ns, Labels: map[string]string{"app.kubernetes.io/name": "opservo-k8s-agent"}},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{"agent_id": id, "secret_key": key},
	}
	_, err := c.Core.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		_, err = c.Core.CoreV1().Secrets(ns).Update(ctx, sec, metav1.UpdateOptions{})
	}
	if err != nil {
		return fmt.Errorf("write %s/%s: %w", ns, credentialsSecret, err)
	}
	return nil
}
