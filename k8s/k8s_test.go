package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
	metricsfake "k8s.io/metrics/pkg/client/clientset/versioned/fake"
)

var now = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func q(s string) resource.Quantity { return resource.MustParse(s) }

func i32(v int32) *int32 { return &v }

func container(name, image, cpuReq, memReq string) corev1.Container {
	c := corev1.Container{Name: name, Image: image, Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{}, Limits: corev1.ResourceList{}}}
	if cpuReq != "" {
		c.Resources.Requests[corev1.ResourceCPU] = q(cpuReq)
		c.Resources.Limits[corev1.ResourceCPU] = q(cpuReq)
	}
	if memReq != "" {
		c.Resources.Requests[corev1.ResourceMemory] = q(memReq)
		c.Resources.Limits[corev1.ResourceMemory] = q(memReq)
	}
	return c
}

// fixture builds a small but realistic cluster: 2 nodes (one NotReady with
// MemoryPressure), a healthy deployment, a crashlooping deployment with no
// requests, an unschedulable pending pod, a completed job pod, an HPA and a PDB.
func fixture() []runtime.Object {
	labelsWeb := map[string]string{"app": "web"}
	labelsCheckout := map[string]string{"app": "checkout"}
	objs := []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("cluster-uid-1")}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a", Labels: map[string]string{"node.kubernetes.io/instance-type": "t3.large", "topology.kubernetes.io/zone": "us-east-1a"}},
			Spec:       corev1.NodeSpec{ProviderID: "aws:///us-east-1a/i-0abc"},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{corev1.ResourceCPU: q("2000m"), corev1.ResourceMemory: q("8Gi"), corev1.ResourcePods: q("110")},
				Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				NodeInfo:    corev1.NodeSystemInfo{KubeletVersion: "v1.30.2-eks-1234", OSImage: "Amazon Linux 2023"},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-b"},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{corev1.ResourceCPU: q("2000m"), corev1.ResourceMemory: q("8Gi"), corev1.ResourcePods: q("110")},
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
					{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue},
				},
				NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.30.2-eks-1234"},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"},
			Spec: appsv1.DeploymentSpec{Replicas: i32(2), Selector: &metav1.LabelSelector{MatchLabels: labelsWeb},
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labelsWeb}, Spec: corev1.PodSpec{Containers: []corev1.Container{container("web", "shop/web:1.2", "500m", "512Mi")}}}},
			Status: appsv1.DeploymentStatus{ReadyReplicas: 2, AvailableReplicas: 2},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "shop"},
			Spec: appsv1.DeploymentSpec{Replicas: i32(3), Selector: &metav1.LabelSelector{MatchLabels: labelsCheckout},
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labelsCheckout}, Spec: corev1.PodSpec{Containers: []corev1.Container{container("checkout", "shop/checkout:9", "", "")}}}},
			Status: appsv1.DeploymentStatus{ReadyReplicas: 1, AvailableReplicas: 1},
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "node-exporter", Namespace: "kube-system"},
			Spec:       appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "ne"}}, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{container("ne", "prom/node-exporter", "50m", "64Mi")}}}},
			Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 2, NumberReady: 2, NumberAvailable: 2, UpdatedNumberScheduled: 2},
		},
		&autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "web"},
				MinReplicas:    i32(2), MaxReplicas: 10,
				Metrics: []autoscalingv2.MetricSpec{{Type: autoscalingv2.ResourceMetricSourceType, Resource: &autoscalingv2.ResourceMetricSource{Name: corev1.ResourceCPU, Target: autoscalingv2.MetricTarget{AverageUtilization: i32(70)}}}},
			},
		},
		&policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"},
			Spec:       policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: labelsWeb}},
		},
		&corev1.Event{
			ObjectMeta: metav1.ObjectMeta{Name: "ev1", Namespace: "shop"},
			Type:       "Warning", Reason: "BackOff", Message: "Back-off restarting failed container",
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "checkout-7d9f-1"},
			Count:          12, LastTimestamp: metav1.NewTime(now.Add(-2 * time.Minute)),
		},
		&corev1.Event{ // duplicate key → folded
			ObjectMeta: metav1.ObjectMeta{Name: "ev2", Namespace: "shop"},
			Type:       "Warning", Reason: "BackOff", Message: "Back-off restarting failed container (again)",
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "checkout-7d9f-1"},
			Count:          3, LastTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
		},
		&corev1.Event{ // too old → dropped
			ObjectMeta: metav1.ObjectMeta{Name: "ev3", Namespace: "shop"},
			Type:       "Warning", Reason: "Unhealthy", Message: "old",
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1"},
			Count:          1, LastTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)),
		},
	}
	rsOwner := func(name string) []metav1.OwnerReference {
		return []metav1.OwnerReference{{Kind: "ReplicaSet", Name: name}}
	}
	created := metav1.NewTime(now.Add(-30 * time.Minute))
	for i := 0; i < 2; i++ {
		objs = append(objs, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-abc-" + string(rune('1'+i)), Namespace: "shop", Labels: labelsWeb, OwnerReferences: rsOwner("web-abc"), CreationTimestamp: created},
			Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{container("web", "shop/web:1.2", "500m", "512Mi")}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "web", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}},
		})
	}
	objs = append(objs,
		&corev1.Pod{ // crashloop, OOM last time
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-7d9f-1", Namespace: "shop", Labels: labelsCheckout, OwnerReferences: rsOwner("checkout-7d9f"), CreationTimestamp: created},
			Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{container("checkout", "shop/checkout:9", "", "")}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
				Name: "checkout", RestartCount: 14,
				State:                corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: "back-off 5m0s restarting failed container"}},
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled"}},
			}}},
		},
		&corev1.Pod{ // image pull
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-7d9f-2", Namespace: "shop", Labels: labelsCheckout, OwnerReferences: rsOwner("checkout-7d9f"), CreationTimestamp: created},
			Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{container("checkout", "shop/checkout:9", "", "")}},
			Status: corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{
				Name: "checkout", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: `Back-off pulling image "shop/checkout:9"`}},
			}}},
		},
		&corev1.Pod{ // healthy checkout replica
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-7d9f-3", Namespace: "shop", Labels: labelsCheckout, OwnerReferences: rsOwner("checkout-7d9f"), CreationTimestamp: created},
			Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{container("checkout", "shop/checkout:9", "", "")}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "checkout", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}},
		},
		&corev1.Pod{ // unschedulable
			ObjectMeta: metav1.ObjectMeta{Name: "bigjob-x", Namespace: "shop", CreationTimestamp: created},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{container("big", "shop/big", "16", "64Gi")}},
			Status: corev1.PodStatus{Phase: corev1.PodPending, Conditions: []corev1.PodCondition{{
				Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: "Unschedulable", Message: "0/2 nodes are available: 2 Insufficient cpu.",
			}}},
		},
		&corev1.Pod{ // completed job — never a problem
			ObjectMeta: metav1.ObjectMeta{Name: "migrate-1", Namespace: "shop", OwnerReferences: []metav1.OwnerReference{{Kind: "Job", Name: "migrate"}}, CreationTimestamp: created},
			Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{container("m", "shop/migrate", "100m", "128Mi")}},
			Status:     corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{Name: "m", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, Reason: "Completed"}}}}},
		},
	)
	return objs
}

func testClients(withMetrics bool) *Clients {
	c := &Clients{Core: fake.NewSimpleClientset(fixture()...)}
	if withMetrics {
		// The metrics fake lists under resource "nodes"/"pods" (not the guessed
		// "nodemetrics"), so seed the tracker with those GVRs explicitly.
		m := metricsfake.NewSimpleClientset()
		nodesGVR := schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "nodes"}
		podsGVR := schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "pods"}
		_ = m.Tracker().Create(nodesGVR, &metricsv1beta1.NodeMetrics{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Usage: corev1.ResourceList{corev1.ResourceCPU: q("1200m"), corev1.ResourceMemory: q("4Gi")}}, "")
		_ = m.Tracker().Create(podsGVR, &metricsv1beta1.PodMetrics{ObjectMeta: metav1.ObjectMeta{Name: "web-abc-1", Namespace: "shop"}, Containers: []metricsv1beta1.ContainerMetrics{{Name: "web", Usage: corev1.ResourceList{corev1.ResourceCPU: q("50m"), corev1.ResourceMemory: q("100Mi")}}}}, "shop")
		_ = m.Tracker().Create(podsGVR, &metricsv1beta1.PodMetrics{ObjectMeta: metav1.ObjectMeta{Name: "web-abc-2", Namespace: "shop"}, Containers: []metricsv1beta1.ContainerMetrics{{Name: "web", Usage: corev1.ResourceList{corev1.ResourceCPU: q("70m"), corev1.ResourceMemory: q("140Mi")}}}}, "shop")
		c.Metrics = m
	}
	return c
}

func TestCollectCluster(t *testing.T) {
	c := testClients(true)
	pods, err := listPods(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	cl, nodes, err := collectCluster(context.Background(), c, pods, "prod-eks")
	if err != nil {
		t.Fatal(err)
	}
	if cl.UID != "cluster-uid-1" || cl.NodeCount != 2 || cl.ReadyNodes != 1 || cl.NamespaceCount != 2 || !cl.MetricsServer {
		t.Fatalf("cluster roll-up wrong: %+v", cl)
	}
	if cl.Platform != "eks" {
		t.Fatalf("platform from providerID should be eks, got %q", cl.Platform)
	}
	var a, b Node
	for _, n := range nodes {
		if n.Name == "node-a" {
			a = n
		} else {
			b = n
		}
	}
	// node-a: 2 web pods (500m each) + 3 checkout (0) + migrate (succeeded → excluded) = 1000m requests
	if a.CPURequestsM != 1000 || a.PodCount != 5 || a.CPUUsageM != 1200 || a.CPUUsagePercent != 60 || a.CPURequestsPct != 50 {
		t.Fatalf("node-a numbers wrong: %+v", a)
	}
	if a.InstanceType != "t3.large" || a.Zone != "us-east-1a" || !a.Ready {
		t.Fatalf("node-a labels/ready wrong: %+v", a)
	}
	if b.Ready || len(b.Conditions) != 1 || b.Conditions[0] != "MemoryPressure" || b.CPUUsageM != 0 {
		t.Fatalf("node-b should be NotReady with MemoryPressure and no metrics: %+v", b)
	}
}

func TestCollectClusterWithoutMetricsServer(t *testing.T) {
	c := testClients(false)
	pods, _ := listPods(context.Background(), c)
	cl, nodes, err := collectCluster(context.Background(), c, pods, "x")
	if err != nil {
		t.Fatal(err)
	}
	if cl.MetricsServer {
		t.Fatal("metrics server should be reported absent")
	}
	for _, n := range nodes {
		if n.CPUUsageM != 0 || n.CPUUsagePercent != 0 {
			t.Fatalf("usage must be zero without metrics-server: %+v", n)
		}
	}
}

func TestCollectPodsClassifies(t *testing.T) {
	c := testClients(false)
	pods, _ := listPods(context.Background(), c)
	sum := collectPods(context.Background(), c, pods, now)
	if sum.Total != 7 || sum.Running != 4 || sum.Pending != 2 || sum.Succeeded != 1 {
		t.Fatalf("phase counts wrong: %+v", sum)
	}
	if len(sum.Problems) != 3 {
		t.Fatalf("expected 3 problem pods (crashloop, imagepull, unschedulable), got %d: %+v", len(sum.Problems), sum.Problems)
	}
	first := sum.Problems[0]
	if first.Name != "checkout-7d9f-1" || first.Reason != "OOMKilled" || first.ExitCode != 137 || first.Restarts != 14 || first.Owner != "Deployment/checkout" {
		t.Fatalf("crashloop pod should sort first and carry OOM context: %+v", first)
	}
	if first.LastLog != "fake logs" { // the fake clientset's GetLogs body
		t.Fatalf("expected the previous-container log tail, got %q", first.LastLog)
	}
	if sum.Problems[1].Reason != "ImagePullBackOff" || sum.Problems[1].LastLog != "" {
		t.Fatalf("image pull pod wrong (and must not fetch logs): %+v", sum.Problems[1])
	}
	if sum.Problems[2].Reason != "Unschedulable" || !strings.Contains(sum.Problems[2].Message, "Insufficient cpu") {
		t.Fatalf("unschedulable pod wrong: %+v", sum.Problems[2])
	}
}

func TestCollectWorkloadsAndResources(t *testing.T) {
	c := testClients(true)
	pods, _ := listPods(context.Background(), c)
	sum := collectPods(context.Background(), c, pods, now)
	ws, err := collectWorkloads(context.Background(), c, pods, sum.Problems)
	if err != nil {
		t.Fatal(err)
	}
	if err := collectResources(context.Background(), c, ws, pods); err != nil {
		t.Fatal(err)
	}
	byName := map[string]Workload{}
	for _, w := range ws {
		byName[w.Kind+"/"+w.Name] = w
	}
	web := byName["Deployment/web"]
	if web.Status != "ok" || web.Desired != 2 || web.Ready != 2 || web.NoRequests || !web.HasHPA || !web.HasPDB || web.HPATargetCPU != 70 || web.HPAMax != 10 {
		t.Fatalf("web wrong: %+v", web)
	}
	// avg usage per replica: (50+70)/2 = 60m of a 500m request = 12%
	if web.CPUUsageM != 60 || web.CPUUsagePct != 12 || web.MemUsageB != 120*1024*1024 {
		t.Fatalf("web usage wrong: cpu=%d pct=%v mem=%d", web.CPUUsageM, web.CPUUsagePct, web.MemUsageB)
	}
	co := byName["Deployment/checkout"]
	if co.Status != "degraded" || co.Restarts != 14 || co.ProblemPods != 2 || !co.NoRequests || co.HasHPA || co.HasPDB {
		t.Fatalf("checkout wrong: %+v", co)
	}
	ne := byName["DaemonSet/node-exporter"]
	if ne.Status != "ok" || ne.Desired != 2 {
		t.Fatalf("daemonset wrong: %+v", ne)
	}
}

func TestCollectEventsDedupes(t *testing.T) {
	c := testClients(false)
	evs, err := collectEvents(context.Background(), c, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected the two BackOff events folded and the old one dropped, got %+v", evs)
	}
	if evs[0].Count != 15 || evs[0].Reason != "BackOff" || !strings.Contains(evs[0].Message, "again") {
		t.Fatalf("folded event wrong: %+v", evs[0])
	}
}

const sampleMetrics = `# HELP apiserver_request_duration_seconds Response latency distribution in seconds for each verb.
# TYPE apiserver_request_duration_seconds histogram
apiserver_request_duration_seconds_bucket{verb="GET",le="0.05"} 900
apiserver_request_duration_seconds_bucket{verb="GET",le="0.1"} 990
apiserver_request_duration_seconds_bucket{verb="GET",le="1"} 1000
apiserver_request_duration_seconds_bucket{verb="GET",le="+Inf"} 1000
apiserver_request_duration_seconds_bucket{verb="LIST",le="0.5"} 50
apiserver_request_duration_seconds_bucket{verb="LIST",le="2"} 95
apiserver_request_duration_seconds_bucket{verb="LIST",le="+Inf"} 100
apiserver_request_duration_seconds_bucket{verb="WATCH",le="+Inf"} 5000
apiserver_request_total{code="200",verb="GET"} 980
apiserver_request_total{code="500",verb="GET"} 20
etcd_request_duration_seconds_bucket{operation="get",le="0.01"} 400
etcd_request_duration_seconds_bucket{operation="get",le="0.1"} 495
etcd_request_duration_seconds_bucket{operation="get",le="+Inf"} 500
`

func TestParseAPIServerMetrics(t *testing.T) {
	a := parseAPIServerMetrics([]byte(sampleMetrics))
	if a.ByVerb["GET"].P50Ms <= 0 || a.ByVerb["GET"].P50Ms > 50 {
		t.Fatalf("GET p50 should be within the first bucket, got %v", a.ByVerb["GET"].P50Ms)
	}
	if a.ByVerb["GET"].P99Ms < 100 || a.ByVerb["GET"].P99Ms > 1000 {
		t.Fatalf("GET p99 should land in the 0.1–1 s bucket, got %v", a.ByVerb["GET"].P99Ms)
	}
	if a.ByVerb["LIST"].P99Ms < 500 || a.ByVerb["LIST"].P99Ms > 2000 {
		t.Fatalf("LIST p99 wrong: %v", a.ByVerb["LIST"].P99Ms)
	}
	if _, ok := a.ByVerb["WATCH"]; ok {
		t.Fatal("WATCH must be excluded")
	}
	if !a.EtcdVisible || a.EtcdP99Ms < 10 || a.EtcdP99Ms > 100 {
		t.Fatalf("etcd p99 wrong: visible=%v p99=%v", a.EtcdVisible, a.EtcdP99Ms)
	}
	if a.Errors5xxPct != 2 {
		t.Fatalf("5xx rate should be 2%%, got %v", a.Errors5xxPct)
	}
}

func TestParseSample(t *testing.T) {
	name, labels, v, ok := parseSample(`foo_bucket{verb="GET",le="+Inf",path="a,b"} 12 1700000000`)
	if !ok || name != "foo_bucket" || labels["verb"] != "GET" || labels["le"] != "+Inf" || labels["path"] != "a,b" || v != 12 {
		t.Fatalf("parse wrong: %q %v %v %v", name, labels, v, ok)
	}
	if _, _, _, ok := parseSample("garbage"); ok {
		t.Fatal("garbage must not parse")
	}
}

func TestCollectorEndToEnd(t *testing.T) {
	c := testClients(true)
	c.RawMetrics = func(context.Context) ([]byte, error) { return []byte(sampleMetrics), nil }
	col := New(c, "prod-eks")
	col.now = func() time.Time { return now }
	out, err := col.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snap := out.(*Snapshot)
	if snap.Cluster.Name != "prod-eks" || len(snap.Nodes) != 2 || snap.APIServer == nil || len(snap.Workloads) != 3 || len(snap.Pods.Problems) != 3 || len(snap.Events) != 1 {
		t.Fatalf("snapshot incomplete: %+v", snap)
	}
	if snap.Errors != nil {
		t.Fatalf("no sub-collector should fail: %v", snap.Errors)
	}
	// JSON shape the API reads.
	b, _ := json.Marshal(snap)
	for _, key := range []string{`"cluster"`, `"nodes"`, `"apiserver"`, `"workloads"`, `"pods"`, `"events"`, `"problems"`, `"last_log"`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("json missing %s", key)
		}
	}
}

func TestCollectorDegradesPerStep(t *testing.T) {
	c := testClients(false)
	c.RawMetrics = func(context.Context) ([]byte, error) { return nil, errors.New("forbidden: metrics") }
	col := New(c, "x")
	col.now = func() time.Time { return now }
	out, _ := col.Collect(context.Background())
	snap := out.(*Snapshot)
	if snap.APIServer != nil || !strings.Contains(snap.Errors["apiserver"], "forbidden") {
		t.Fatalf("apiserver step should record its error only: %+v", snap.Errors)
	}
	if len(snap.Workloads) != 3 || len(snap.Nodes) != 2 {
		t.Fatal("other steps must still run")
	}
}

func TestClassifyPodFlapping(t *testing.T) {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "n", CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute))},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "c", RestartCount: 7, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error"}},
		}}},
	}
	pp, ok := classifyPod(p, now)
	if !ok || pp.Reason != "Restarting" || pp.Container != "c" || pp.ExitCode != 1 {
		t.Fatalf("flapping pod should be flagged: %+v ok=%v", pp, ok)
	}
	// Terminating pods are transient, never problems.
	del := metav1.NewTime(now)
	p.DeletionTimestamp = &del
	if _, ok := classifyPod(p, now); ok {
		t.Fatal("terminating pod must not be flagged")
	}
}
