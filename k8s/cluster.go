package k8s

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// collectCluster fills Cluster + Nodes. Node requests/limits are summed from
// the pod list (passed in so pods are listed once per heartbeat), live usage
// comes from metrics.k8s.io when present.
func collectCluster(ctx context.Context, c *Clients, pods []corev1.Pod, name string) (Cluster, []Node, error) {
	cl := Cluster{Name: name}

	if v, err := c.Core.Discovery().ServerVersion(); err == nil && v != nil {
		cl.Version = v.GitVersion
		cl.Platform = platformFromVersion(v.GitVersion)
	}
	if ks, err := c.Core.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{}); err == nil {
		cl.UID = string(ks.UID)
	}
	if nsl, err := c.Core.CoreV1().Namespaces().List(ctx, metav1.ListOptions{}); err == nil {
		cl.NamespaceCount = len(nsl.Items)
	}

	nl, err := c.Core.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return cl, nil, fmt.Errorf("list nodes: %w", err)
	}

	// Requests/limits per node from the scheduled (non-terminal) pods.
	type sums struct {
		cpuReq, cpuLim, memReq, memLim int64
		pods                           int
	}
	perNode := map[string]*sums{}
	for i := range pods {
		p := &pods[i]
		if p.Spec.NodeName == "" || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		s := perNode[p.Spec.NodeName]
		if s == nil {
			s = &sums{}
			perNode[p.Spec.NodeName] = s
		}
		cr, cl2, mr, ml := podResources(p)
		s.cpuReq += cr
		s.cpuLim += cl2
		s.memReq += mr
		s.memLim += ml
		s.pods++
	}

	usage := map[string][2]int64{} // name → {cpu millicores, mem bytes}
	if c.Metrics != nil {
		if nm, err := c.Metrics.MetricsV1beta1().NodeMetricses().List(ctx, metav1.ListOptions{}); err == nil {
			cl.MetricsServer = true
			for _, m := range nm.Items {
				usage[m.Name] = [2]int64{m.Usage.Cpu().MilliValue(), m.Usage.Memory().Value()}
			}
		}
	}

	nodes := make([]Node, 0, len(nl.Items))
	for _, n := range nl.Items {
		node := Node{
			Name:            n.Name,
			Unschedulable:   n.Spec.Unschedulable,
			KubeletVersion:  n.Status.NodeInfo.KubeletVersion,
			OSImage:         n.Status.NodeInfo.OSImage,
			InstanceType:    firstLabel(n.Labels, "node.kubernetes.io/instance-type", "beta.kubernetes.io/instance-type"),
			Zone:            firstLabel(n.Labels, "topology.kubernetes.io/zone", "failure-domain.beta.kubernetes.io/zone"),
			CPUAllocatableM: n.Status.Allocatable.Cpu().MilliValue(),
			MemAllocatableB: n.Status.Allocatable.Memory().Value(),
			PodCapacity:     n.Status.Allocatable.Pods().Value(),
		}
		for _, cond := range n.Status.Conditions {
			switch {
			case cond.Type == corev1.NodeReady:
				node.Ready = cond.Status == corev1.ConditionTrue
			case cond.Status == corev1.ConditionTrue:
				node.Conditions = append(node.Conditions, string(cond.Type))
			}
		}
		if node.Ready {
			cl.ReadyNodes++
		}
		if s := perNode[n.Name]; s != nil {
			node.CPURequestsM, node.CPULimitsM, node.MemRequestsB, node.MemLimitsB, node.PodCount = s.cpuReq, s.cpuLim, s.memReq, s.memLim, s.pods
		}
		if u, ok := usage[n.Name]; ok {
			node.CPUUsageM, node.MemUsageB = u[0], u[1]
		}
		node.CPUUsagePercent = pct(node.CPUUsageM, node.CPUAllocatableM)
		node.MemUsagePercent = pct(node.MemUsageB, node.MemAllocatableB)
		node.CPURequestsPct = pct(node.CPURequestsM, node.CPUAllocatableM)
		node.MemRequestsPct = pct(node.MemRequestsB, node.MemAllocatableB)
		nodes = append(nodes, node)
	}
	cl.NodeCount = len(nodes)
	if cl.Platform == "" || cl.Platform == "other" {
		cl.Platform = platformFromNodes(nl.Items, cl.Platform)
	}
	return cl, nodes, nil
}

// podResources sums container requests/limits for one pod (millicores, bytes).
func podResources(p *corev1.Pod) (cpuReq, cpuLim, memReq, memLim int64) {
	for _, ct := range p.Spec.Containers {
		cpuReq += ct.Resources.Requests.Cpu().MilliValue()
		cpuLim += ct.Resources.Limits.Cpu().MilliValue()
		memReq += ct.Resources.Requests.Memory().Value()
		memLim += ct.Resources.Limits.Memory().Value()
	}
	return
}

func pct(part, whole int64) float64 {
	if whole <= 0 || part <= 0 {
		return 0
	}
	v := float64(part) / float64(whole) * 100
	return float64(int(v*10+0.5)) / 10
}

func firstLabel(labels map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := labels[k]; v != "" {
			return v
		}
	}
	return ""
}

// platformFromVersion recognises distributions that stamp the server version.
func platformFromVersion(gitVersion string) string {
	v := strings.ToLower(gitVersion)
	switch {
	case strings.Contains(v, "gke"):
		return "gke"
	case strings.Contains(v, "eks"):
		return "eks"
	case strings.Contains(v, "k3s"):
		return "k3s"
	case strings.Contains(v, "rke2"):
		return "rke2"
	}
	return "other"
}

// platformFromNodes falls back to provider IDs / labels (AKS and kind don't
// stamp the version string).
func platformFromNodes(nodes []corev1.Node, current string) string {
	for _, n := range nodes {
		pid := strings.ToLower(n.Spec.ProviderID)
		switch {
		case strings.HasPrefix(pid, "azure://"):
			return "aks"
		case strings.HasPrefix(pid, "aws://"):
			return "eks"
		case strings.HasPrefix(pid, "gce://"):
			return "gke"
		case strings.HasPrefix(pid, "kind://"):
			return "kind"
		case strings.HasPrefix(pid, "k3s://"):
			return "k3s"
		}
		if _, ok := n.Labels["kubernetes.azure.com/cluster"]; ok {
			return "aks"
		}
	}
	if current == "" {
		return "other"
	}
	return current
}
