package k8s

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/getopservo/opservo-agent/collectors"
)

const (
	maxProblemPods = 40
	logTailLines   = 50
	logTailBytes   = 8 * 1024
)

// listPods lists every pod once per heartbeat; the other sub-collectors share
// the slice so the API server is not asked five times.
func listPods(ctx context.Context, c *Clients) ([]corev1.Pod, error) {
	pl, err := c.Core.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	return pl.Items, nil
}

// collectPods reduces the pod list to phase counts + the pods that need a
// human, each with the reason, message, exit code and (for crashing
// containers) the tail of the previous instance's log.
func collectPods(ctx context.Context, c *Clients, pods []corev1.Pod, now time.Time) PodSummary {
	sum := PodSummary{Problems: []ProblemPod{}}
	for i := range pods {
		p := &pods[i]
		sum.Total++
		switch p.Status.Phase {
		case corev1.PodRunning:
			sum.Running++
		case corev1.PodPending:
			sum.Pending++
		case corev1.PodSucceeded:
			sum.Succeeded++
		case corev1.PodFailed:
			sum.Failed++
		default:
			sum.Unknown++
		}
		if pp, ok := classifyPod(p, now); ok {
			if pp.Reason == "CrashLoopBackOff" || pp.Reason == "Error" || pp.Reason == "OOMKilled" {
				pp.LastLog = tailPreviousLog(ctx, c, p.Namespace, p.Name, pp.Container)
			}
			sum.Problems = append(sum.Problems, pp)
		}
	}
	// Worst first: crashloops, then image pulls, then pending; newest restarts first.
	sort.SliceStable(sum.Problems, func(i, j int) bool {
		ri, rj := reasonRank(sum.Problems[i].Reason), reasonRank(sum.Problems[j].Reason)
		if ri != rj {
			return ri < rj
		}
		return sum.Problems[i].Restarts > sum.Problems[j].Restarts
	})
	if len(sum.Problems) > maxProblemPods {
		sum.Problems = sum.Problems[:maxProblemPods]
	}
	return sum
}

func reasonRank(r string) int {
	switch r {
	case "CrashLoopBackOff", "OOMKilled":
		return 0
	case "Error", "CreateContainerConfigError", "CreateContainerError":
		return 1
	case "ImagePullBackOff", "ErrImagePull", "InvalidImageName":
		return 2
	case "Unschedulable":
		return 3
	}
	return 4
}

// classifyPod decides whether a pod is a problem and why. Succeeded pods
// (completed Jobs) are never problems; Pending is a problem only when the
// scheduler said so or it has been pending > 5 minutes.
func classifyPod(p *corev1.Pod, now time.Time) (ProblemPod, bool) {
	pp := ProblemPod{
		Namespace: p.Namespace, Name: p.Name, Node: p.Spec.NodeName, Phase: string(p.Status.Phase),
		Owner: ownerOf(p), SinceMinute: int64(now.Sub(p.CreationTimestamp.Time).Minutes()),
	}
	if p.Status.Phase == corev1.PodSucceeded {
		return pp, false
	}
	if p.DeletionTimestamp != nil {
		return pp, false // terminating — transient
	}
	statuses := append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...)
	statuses = append(statuses, p.Status.ContainerStatuses...)
	for _, cs := range statuses {
		pp.Restarts += cs.RestartCount
	}
	for _, cs := range statuses {
		if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "ContainerCreating" && w.Reason != "PodInitializing" {
			pp.Reason, pp.Message, pp.Container = w.Reason, oneLine(w.Message), cs.Name
			if t := cs.LastTerminationState.Terminated; t != nil {
				pp.ExitCode = t.ExitCode
				if t.Reason == "OOMKilled" {
					pp.Reason = "OOMKilled"
				}
				if pp.Message == "" {
					pp.Message = oneLine(t.Message)
				}
				if pp.Message == "" && t.Reason != "" {
					pp.Message = fmt.Sprintf("last exit %d (%s)", t.ExitCode, t.Reason)
				}
			}
			return pp, true
		}
		if t := cs.State.Terminated; t != nil && t.ExitCode != 0 && p.Status.Phase != corev1.PodSucceeded {
			pp.Reason, pp.Container, pp.ExitCode = t.Reason, cs.Name, t.ExitCode
			if pp.Reason == "" {
				pp.Reason = "Error"
			}
			pp.Message = oneLine(t.Message)
			return pp, true
		}
	}
	if p.Status.Phase == corev1.PodPending {
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse {
				pp.Reason = "Unschedulable"
				if c.Reason != "" && c.Reason != "Unschedulable" {
					pp.Reason = c.Reason
				}
				pp.Message = oneLine(c.Message)
				return pp, true
			}
		}
		if now.Sub(p.CreationTimestamp.Time) > 5*time.Minute {
			pp.Reason, pp.Message = "Pending", "pending for more than 5 minutes"
			return pp, true
		}
	}
	if p.Status.Phase == corev1.PodFailed {
		pp.Reason = p.Status.Reason
		if pp.Reason == "" {
			pp.Reason = "Failed"
		}
		pp.Message = oneLine(p.Status.Message)
		return pp, true
	}
	// Running but flapping: many restarts in a short life.
	if p.Status.Phase == corev1.PodRunning && pp.Restarts >= 5 && now.Sub(p.CreationTimestamp.Time) < 6*time.Hour {
		pp.Reason, pp.Message = "Restarting", fmt.Sprintf("%d restarts in %s", pp.Restarts, now.Sub(p.CreationTimestamp.Time).Round(time.Minute))
		for _, cs := range statuses {
			if cs.RestartCount > 0 {
				pp.Container = cs.Name
				if t := cs.LastTerminationState.Terminated; t != nil {
					pp.ExitCode = t.ExitCode
					if t.Reason == "OOMKilled" {
						pp.Reason = "OOMKilled"
					}
				}
				break
			}
		}
		return pp, true
	}
	return pp, false
}

// ownerOf renders "Deployment/checkout" by walking ReplicaSet → Deployment
// naming (the RS carries the pod-template hash suffix).
func ownerOf(p *corev1.Pod) string {
	for _, o := range p.OwnerReferences {
		switch o.Kind {
		case "ReplicaSet":
			name := o.Name
			if i := strings.LastIndexByte(name, '-'); i > 0 {
				name = name[:i]
			}
			return "Deployment/" + name
		case "StatefulSet", "DaemonSet", "Job", "CronJob":
			return o.Kind + "/" + o.Name
		}
	}
	return ""
}

// tailPreviousLog returns the last lines of the crashing container's PREVIOUS
// run (the one that exited) — that is where the stack trace lives. Falls back
// to the current instance when there is no previous one. Capped hard.
func tailPreviousLog(ctx context.Context, c *Clients, ns, pod, container string) string {
	if container == "" {
		return ""
	}
	tail := int64(logTailLines)
	limit := int64(logTailBytes)
	for _, prev := range []bool{true, false} {
		req := c.Core.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{Container: container, TailLines: &tail, LimitBytes: &limit, Previous: prev})
		rc, err := req.Stream(ctx)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rc, logTailBytes))
		rc.Close()
		if s := strings.TrimSpace(string(b)); s != "" {
			// A crashing app dumps its config/env into the stack trace more
			// often than not; same per-line masking the Linux log collector
			// applies before anything leaves the box.
			return redactLines(s)
		}
	}
	return ""
}

// redactLines runs collectors.RedactSecrets over each line of a log tail
// (its generic rules stop at whitespace, so a line at a time is the unit).
func redactLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = collectors.RedactSecrets(l)
	}
	return strings.Join(lines, "\n")
}

func oneLine(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}

// collectWorkloads lists Deployments / StatefulSets / DaemonSets with
// readiness + the pods that belong to them (by namespace + label selector).
func collectWorkloads(ctx context.Context, c *Clients, pods []corev1.Pod, problems []ProblemPod) ([]Workload, error) {
	var out []Workload
	problemByOwner := map[string]int{}
	for _, pp := range problems {
		problemByOwner[pp.Namespace+"/"+pp.Owner]++
	}

	dl, err := c.Core.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	for _, d := range dl.Items {
		w := Workload{Namespace: d.Namespace, Kind: "Deployment", Name: d.Name, Desired: derefInt32(d.Spec.Replicas, 1),
			Ready: d.Status.ReadyReplicas, Available: d.Status.AvailableReplicas}
		fillFromTemplate(&w, &d.Spec.Template)
		fillFromPods(&w, pods, d.Namespace, d.Spec.Selector)
		w.ProblemPods = problemByOwner[d.Namespace+"/Deployment/"+d.Name]
		w.Status = workloadStatus(w, isProgressing(d.Status.Conditions))
		out = append(out, w)
	}
	sl, err := c.Core.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, fmt.Errorf("list statefulsets: %w", err)
	}
	for _, s := range sl.Items {
		w := Workload{Namespace: s.Namespace, Kind: "StatefulSet", Name: s.Name, Desired: derefInt32(s.Spec.Replicas, 1),
			Ready: s.Status.ReadyReplicas, Available: s.Status.AvailableReplicas}
		fillFromTemplate(&w, &s.Spec.Template)
		fillFromPods(&w, pods, s.Namespace, s.Spec.Selector)
		w.ProblemPods = problemByOwner[s.Namespace+"/StatefulSet/"+s.Name]
		w.Status = workloadStatus(w, s.Status.UpdatedReplicas < w.Desired && s.Status.UpdateRevision != s.Status.CurrentRevision)
		out = append(out, w)
	}
	dsl, err := c.Core.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return out, fmt.Errorf("list daemonsets: %w", err)
	}
	for _, ds := range dsl.Items {
		w := Workload{Namespace: ds.Namespace, Kind: "DaemonSet", Name: ds.Name, Desired: ds.Status.DesiredNumberScheduled,
			Ready: ds.Status.NumberReady, Available: ds.Status.NumberAvailable}
		fillFromTemplate(&w, &ds.Spec.Template)
		fillFromPods(&w, pods, ds.Namespace, ds.Spec.Selector)
		w.ProblemPods = problemByOwner[ds.Namespace+"/DaemonSet/"+ds.Name]
		w.Status = workloadStatus(w, ds.Status.UpdatedNumberScheduled < ds.Status.DesiredNumberScheduled)
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func derefInt32(p *int32, def int32) int32 {
	if p == nil {
		return def
	}
	return *p
}

func isProgressing(conds []appsv1.DeploymentCondition) bool {
	for _, c := range conds {
		if c.Type == appsv1.DeploymentProgressing && c.Status == corev1.ConditionTrue && c.Reason == "ReplicaSetUpdated" {
			return true
		}
	}
	return false
}

// fillFromTemplate records images + per-replica requests/limits from the pod
// template, and whether any container has no request at all.
func fillFromTemplate(w *Workload, t *corev1.PodTemplateSpec) {
	for _, ct := range t.Spec.Containers {
		w.Images = append(w.Images, ct.Image)
		cr := ct.Resources.Requests.Cpu().MilliValue()
		mr := ct.Resources.Requests.Memory().Value()
		if cr == 0 || mr == 0 {
			w.NoRequests = true
		}
		w.CPURequestM += cr
		w.MemRequestB += mr
		w.CPULimitM += ct.Resources.Limits.Cpu().MilliValue()
		w.MemLimitB += ct.Resources.Limits.Memory().Value()
	}
}

// fillFromPods sums restarts over the workload's current pods.
func fillFromPods(w *Workload, pods []corev1.Pod, ns string, sel *metav1.LabelSelector) {
	if sel == nil {
		return
	}
	for i := range pods {
		p := &pods[i]
		if p.Namespace != ns || !matchesSelector(sel, p.Labels) {
			continue
		}
		for _, cs := range p.Status.ContainerStatuses {
			w.Restarts += cs.RestartCount
		}
	}
}

// matchesSelector handles matchLabels + the common matchExpressions operators.
func matchesSelector(sel *metav1.LabelSelector, labels map[string]string) bool {
	for k, v := range sel.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, e := range sel.MatchExpressions {
		v, ok := labels[e.Key]
		switch e.Operator {
		case metav1.LabelSelectorOpIn:
			if !ok || !contains(e.Values, v) {
				return false
			}
		case metav1.LabelSelectorOpNotIn:
			if ok && contains(e.Values, v) {
				return false
			}
		case metav1.LabelSelectorOpExists:
			if !ok {
				return false
			}
		case metav1.LabelSelectorOpDoesNotExist:
			if ok {
				return false
			}
		}
	}
	return true
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func workloadStatus(w Workload, progressing bool) string {
	switch {
	case w.Desired == 0:
		return "scaled-to-zero"
	case w.Ready == 0:
		return "down"
	case w.Ready < w.Desired && progressing:
		return "progressing"
	case w.Ready < w.Desired || w.ProblemPods > 0:
		return "degraded"
	}
	return "ok"
}
