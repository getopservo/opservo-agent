package main

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/getopservo/opservo-agent/k8s"
)

func TestLoadCredentialsReadsTheSecret(t *testing.T) {
	c := &k8s.Clients{Core: fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: credentialsSecret, Namespace: "opservo"},
		Data:       map[string][]byte{"agent_id": []byte("a-1"), "secret_key": []byte("k-1")},
	})}
	id, key := loadCredentials(context.Background(), c, "opservo")
	if id != "a-1" || key != "k-1" {
		t.Fatalf("loadCredentials = %q, %q; want a-1, k-1", id, key)
	}
}

// No Secret yet (first start) must come back empty, not error out, so the
// agent goes on to enrol.
func TestLoadCredentialsMissingSecretIsEmpty(t *testing.T) {
	c := &k8s.Clients{Core: fake.NewSimpleClientset()}
	if id, key := loadCredentials(context.Background(), c, "opservo"); id != "" || key != "" {
		t.Fatalf("loadCredentials = %q, %q; want empty", id, key)
	}
}

// saveCredentials creates the Secret on first enrolment and overwrites it on a
// re-enrolment instead of failing with AlreadyExists.
func TestSaveCredentialsCreatesThenUpdates(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset()
	c := &k8s.Clients{Core: cs}

	if err := saveCredentials(ctx, c, "opservo", "a-1", "k-1"); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := saveCredentials(ctx, c, "opservo", "a-2", "k-2"); err != nil {
		t.Fatalf("second save: %v", err)
	}
	sec, err := cs.CoreV1().Secrets("opservo").Get(ctx, credentialsSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	// The fake clientset does not fold StringData into Data like the API server does.
	if sec.StringData["agent_id"] != "a-2" || sec.StringData["secret_key"] != "k-2" {
		t.Fatalf("secret data = %v; want the second credentials", sec.StringData)
	}
	if sec.Type != corev1.SecretTypeOpaque || sec.Labels["app.kubernetes.io/name"] != "opservo-k8s-agent" {
		t.Fatalf("secret type/labels = %q %v", sec.Type, sec.Labels)
	}
}

func TestClusterIdentityUsesKubeSystemUID(t *testing.T) {
	c := &k8s.Clients{Core: fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("1234-abcd")},
	})}
	if got := clusterIdentity(context.Background(), c); got != "k8s-1234-abcd" {
		t.Fatalf("clusterIdentity = %q; want k8s-1234-abcd", got)
	}
	if got := clusterIdentity(context.Background(), &k8s.Clients{Core: fake.NewSimpleClientset()}); got != "" {
		t.Fatalf("clusterIdentity without kube-system = %q; want empty", got)
	}
}

func TestDefaultClusterName(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_MASTER", "")
	if got := defaultClusterName(); got != "k8s-10-96-0-1" {
		t.Fatalf("in-cluster name = %q", got)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_MASTER", "https://api.example.test:6443")
	if got := defaultClusterName(); got != "api.example.test" {
		t.Fatalf("kubeconfig name = %q", got)
	}
	t.Setenv("KUBERNETES_MASTER", "")
	if got := defaultClusterName(); got != "kubernetes" {
		t.Fatalf("fallback name = %q", got)
	}
}
