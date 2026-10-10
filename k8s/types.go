// Package k8s is the cluster-level collector behind the opservo-k8s-agent
// binary (cmd/k8s-agent). It runs as ONE replica per cluster (a Deployment,
// not a DaemonSet — cluster-scoped facts would be duplicated per node) and
// ships `data.kubernetes` in the ordinary HMAC-signed heartbeat.
//
// Everything here is read-only: the ClusterRole is get/list/watch only, and
// the pod runs non-root with a read-only filesystem.
package k8s

import "time"

// Snapshot is the `data.kubernetes` block of a heartbeat.
type Snapshot struct {
	CollectedAt time.Time         `json:"collected_at"`
	Cluster     Cluster           `json:"cluster"`
	Nodes       []Node            `json:"nodes"`
	APIServer   *APIServer        `json:"apiserver,omitempty"`
	Workloads   []Workload        `json:"workloads"`
	Pods        PodSummary        `json:"pods"`
	Events      []Event           `json:"events"`
	Errors      map[string]string `json:"errors,omitempty"` // per sub-collector, so one RBAC gap never blanks the whole snapshot
}

// Cluster is the version / size roll-up.
type Cluster struct {
	Name           string `json:"name"`
	UID            string `json:"uid"` // kube-system namespace UID — stable cluster identity
	Version        string `json:"version"`
	Platform       string `json:"platform"` // gke | eks | aks | k3s | kind | other
	NodeCount      int    `json:"node_count"`
	ReadyNodes     int    `json:"ready_nodes"`
	NamespaceCount int    `json:"namespace_count"`
	MetricsServer  bool   `json:"metrics_server"` // metrics.k8s.io reachable
}

// Node is one node's conditions + capacity vs requests vs live usage.
type Node struct {
	Name            string   `json:"name"`
	Ready           bool     `json:"ready"`
	Conditions      []string `json:"conditions,omitempty"` // non-Ready true conditions: MemoryPressure, DiskPressure, PIDPressure, NetworkUnavailable
	Unschedulable   bool     `json:"unschedulable"`
	KubeletVersion  string   `json:"kubelet_version"`
	OSImage         string   `json:"os_image"`
	InstanceType    string   `json:"instance_type,omitempty"`
	Zone            string   `json:"zone,omitempty"`
	CPUAllocatableM int64    `json:"cpu_allocatable_m"` // millicores
	CPURequestsM    int64    `json:"cpu_requests_m"`    // sum of pod requests scheduled here
	CPULimitsM      int64    `json:"cpu_limits_m"`
	CPUUsageM       int64    `json:"cpu_usage_m"` // from metrics-server; 0 when absent
	MemAllocatableB int64    `json:"mem_allocatable_bytes"`
	MemRequestsB    int64    `json:"mem_requests_bytes"`
	MemLimitsB      int64    `json:"mem_limits_bytes"`
	MemUsageB       int64    `json:"mem_usage_bytes"`
	PodCount        int      `json:"pod_count"`
	PodCapacity     int64    `json:"pod_capacity"`
	CPUUsagePercent float64  `json:"cpu_usage_percent"` // usage / allocatable, 0 when no metrics
	MemUsagePercent float64  `json:"mem_usage_percent"`
	CPURequestsPct  float64  `json:"cpu_requests_percent"` // requests / allocatable — the scheduler's view
	MemRequestsPct  float64  `json:"mem_requests_percent"`
}

// APIServer holds request-latency percentiles scraped from /metrics.
type APIServer struct {
	RequestP50Ms float64            `json:"request_p50_ms"`
	RequestP99Ms float64            `json:"request_p99_ms"`
	ByVerb       map[string]Latency `json:"by_verb"`
	EtcdP99Ms    float64            `json:"etcd_p99_ms"` // 0 when etcd metrics aren't exposed (managed control planes)
	EtcdVisible  bool               `json:"etcd_visible"`
	Errors5xxPct float64            `json:"errors_5xx_percent"`
}

// Latency is a p50/p99 pair in milliseconds.
type Latency struct {
	P50Ms float64 `json:"p50_ms"`
	P99Ms float64 `json:"p99_ms"`
}

// Workload is a Deployment / StatefulSet / DaemonSet with readiness, restarts
// and the requests-vs-limits-vs-usage view the HPA recommender needs.
type Workload struct {
	Namespace   string   `json:"namespace"`
	Kind        string   `json:"kind"` // Deployment | StatefulSet | DaemonSet
	Name        string   `json:"name"`
	Desired     int32    `json:"desired"`
	Ready       int32    `json:"ready"`
	Available   int32    `json:"available"`
	Restarts    int32    `json:"restarts"` // sum over current pods
	Images      []string `json:"images"`
	Status      string   `json:"status"` // ok | degraded | down | progressing
	ProblemPods int      `json:"problem_pods"`

	// Per-replica resource picture (sum of containers).
	CPURequestM  int64   `json:"cpu_request_m"`
	CPULimitM    int64   `json:"cpu_limit_m"`
	MemRequestB  int64   `json:"mem_request_bytes"`
	MemLimitB    int64   `json:"mem_limit_bytes"`
	CPUUsageM    int64   `json:"cpu_usage_m"`                  // avg per replica from metrics-server
	MemUsageB    int64   `json:"mem_usage_bytes"`              // avg per replica
	CPUUsagePct  float64 `json:"cpu_usage_percent_of_request"` // usage / request; 0 when either is unknown
	MemUsagePct  float64 `json:"mem_usage_percent_of_request"`
	NoRequests   bool    `json:"no_requests"` // at least one container with no cpu/mem request
	HasHPA       bool    `json:"has_hpa"`
	HPATargetCPU int32   `json:"hpa_target_cpu_percent,omitempty"`
	HPAMin       int32   `json:"hpa_min,omitempty"`
	HPAMax       int32   `json:"hpa_max,omitempty"`
	HasPDB       bool    `json:"has_pdb"`
}

// PodSummary: counts by phase plus the pods that need a human (capped).
type PodSummary struct {
	Total     int          `json:"total"`
	Running   int          `json:"running"`
	Pending   int          `json:"pending"`
	Succeeded int          `json:"succeeded"`
	Failed    int          `json:"failed"`
	Unknown   int          `json:"unknown"`
	Problems  []ProblemPod `json:"problems"`
}

// ProblemPod is a pod in CrashLoopBackOff / ImagePullBackOff / OOMKilled /
// Pending-unschedulable etc., with enough context for a root cause.
type ProblemPod struct {
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Owner       string `json:"owner,omitempty"` // Deployment/checkout
	Node        string `json:"node,omitempty"`
	Phase       string `json:"phase"`
	Reason      string `json:"reason"`  // CrashLoopBackOff | ImagePullBackOff | OOMKilled | Unschedulable | Error | CreateContainerConfigError | …
	Message     string `json:"message"` // waiting/terminated message or scheduler message
	Container   string `json:"container,omitempty"`
	Restarts    int32  `json:"restarts"`
	ExitCode    int32  `json:"exit_code,omitempty"`
	LastLog     string `json:"last_log,omitempty"` // last ≤50 lines of the crashing container (previous instance), capped at 8 KB
	SinceMinute int64  `json:"age_minutes"`
}

// Event is a deduped Warning event from the last 15 minutes.
type Event struct {
	Namespace string    `json:"namespace"`
	Kind      string    `json:"kind"` // involved object kind
	Object    string    `json:"object"`
	Reason    string    `json:"reason"`
	Message   string    `json:"message"`
	Count     int32     `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
}
