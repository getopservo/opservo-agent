package k8s

import (
	"context"
	"fmt"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	eventWindow = 15 * time.Minute
	maxEvents   = 60
)

// collectEvents returns Warning events from the last 15 minutes, deduped by
// (namespace, object, reason) keeping the latest occurrence + summed count.
func collectEvents(ctx context.Context, c *Clients, now time.Time) ([]Event, error) {
	el, err := c.Core.CoreV1().Events("").List(ctx, metav1.ListOptions{FieldSelector: "type=Warning"})
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	cutoff := now.Add(-eventWindow)
	byKey := map[string]*Event{}
	for _, e := range el.Items {
		last := e.LastTimestamp.Time
		if last.IsZero() {
			last = e.EventTime.Time
		}
		if last.IsZero() {
			last = e.FirstTimestamp.Time
		}
		if last.Before(cutoff) {
			continue
		}
		key := e.Namespace + "/" + e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name + "/" + e.Reason
		count := e.Count
		if count == 0 {
			count = 1
		}
		if ex := byKey[key]; ex != nil {
			ex.Count += count
			if last.After(ex.LastSeen) {
				ex.LastSeen = last
				ex.Message = oneLine(e.Message)
			}
			continue
		}
		byKey[key] = &Event{
			Namespace: e.Namespace, Kind: e.InvolvedObject.Kind, Object: e.InvolvedObject.Name,
			Reason: e.Reason, Message: oneLine(e.Message), Count: count, LastSeen: last,
		}
	}
	out := make([]Event, 0, len(byKey))
	for _, e := range byKey {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > maxEvents {
		out = out[:maxEvents]
	}
	return out, nil
}
