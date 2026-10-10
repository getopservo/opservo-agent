package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// collectResources decorates workloads with live usage (metrics-server), HPA
// and PodDisruptionBudget presence. Usage is averaged per replica so it is
// directly comparable to the per-replica request from the template.
// Missing metrics-server or missing RBAC on autoscaling/policy degrade to
// "unknown" rather than failing the snapshot.
func collectResources(ctx context.Context, c *Clients, workloads []Workload, pods []corev1.Pod) error {
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Live usage per pod → per workload (avg per replica).
	type acc struct {
		cpu, mem int64
		n        int64
	}
	usageByOwner := map[string]*acc{}
	if c.Metrics != nil {
		pm, err := c.Metrics.MetricsV1beta1().PodMetricses("").List(ctx, metav1.ListOptions{})
		if err != nil {
			note(fmt.Errorf("pod metrics: %w", err))
		} else {
			owner := map[string]string{} // ns/pod → ns/Kind/name
			for i := range pods {
				if o := ownerOf(&pods[i]); o != "" {
					owner[pods[i].Namespace+"/"+pods[i].Name] = pods[i].Namespace + "/" + o
				}
			}
			for _, m := range pm.Items {
				key := owner[m.Namespace+"/"+m.Name]
				if key == "" {
					continue
				}
				a := usageByOwner[key]
				if a == nil {
					a = &acc{}
					usageByOwner[key] = a
				}
				for _, ct := range m.Containers {
					a.cpu += ct.Usage.Cpu().MilliValue()
					a.mem += ct.Usage.Memory().Value()
				}
				a.n++
			}
		}
	}

	hpa := map[string][3]int32{} // ns/Kind/name → {targetCPU, min, max}
	if hl, err := c.Core.AutoscalingV2().HorizontalPodAutoscalers("").List(ctx, metav1.ListOptions{}); err != nil {
		note(fmt.Errorf("list hpa: %w", err))
	} else {
		for _, h := range hl.Items {
			var target int32
			for _, m := range h.Spec.Metrics {
				if m.Resource != nil && m.Resource.Name == corev1.ResourceCPU && m.Resource.Target.AverageUtilization != nil {
					target = *m.Resource.Target.AverageUtilization
				}
			}
			hpa[h.Namespace+"/"+h.Spec.ScaleTargetRef.Kind+"/"+h.Spec.ScaleTargetRef.Name] = [3]int32{target, derefInt32(h.Spec.MinReplicas, 1), h.Spec.MaxReplicas}
		}
	}

	// PDBs match by selector against the workload's template labels; we
	// approximate with "any PDB in the namespace whose selector matches the
	// workload's pods" using the pod list.
	type pdbSel struct {
		ns  string
		sel *metav1.LabelSelector
	}
	var pdbs []pdbSel
	if pl, err := c.Core.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{}); err != nil {
		note(fmt.Errorf("list pdb: %w", err))
	} else {
		for _, p := range pl.Items {
			pdbs = append(pdbs, pdbSel{ns: p.Namespace, sel: p.Spec.Selector})
		}
	}

	for i := range workloads {
		w := &workloads[i]
		key := w.Namespace + "/" + w.Kind + "/" + w.Name
		if a := usageByOwner[key]; a != nil && a.n > 0 {
			w.CPUUsageM = a.cpu / a.n
			w.MemUsageB = a.mem / a.n
			w.CPUUsagePct = pct(w.CPUUsageM, w.CPURequestM)
			w.MemUsagePct = pct(w.MemUsageB, w.MemRequestB)
		}
		if h, ok := hpa[key]; ok {
			w.HasHPA = true
			w.HPATargetCPU, w.HPAMin, w.HPAMax = h[0], h[1], h[2]
		}
		for _, pd := range pdbs {
			if pd.ns != w.Namespace || pd.sel == nil {
				continue
			}
			for j := range pods {
				p := &pods[j]
				if p.Namespace == w.Namespace && ownerOf(p) == w.Kind+"/"+w.Name && matchesSelector(pd.sel, p.Labels) {
					w.HasPDB = true
					break
				}
			}
			if w.HasPDB {
				break
			}
		}
	}
	return firstErr
}
