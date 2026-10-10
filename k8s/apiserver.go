package k8s

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// collectAPIServer scrapes the API server's own /metrics and reduces the
// request-duration histograms to p50/p99 per verb, plus etcd request latency
// when the control plane exposes it (self-managed clusters; GKE/EKS/AKS hide
// etcd, so EtcdVisible=false is normal there). Requires `get` on the
// non-resource URL /metrics — granted by the shipped ClusterRole; when RBAC
// denies it we return (nil, err) and the snapshot records the reason.
func collectAPIServer(ctx context.Context, c *Clients) (*APIServer, error) {
	if c.RawMetrics == nil {
		return nil, fmt.Errorf("apiserver metrics: not available")
	}
	raw, err := c.RawMetrics(ctx)
	if err != nil {
		return nil, fmt.Errorf("apiserver metrics: %w", err)
	}
	return parseAPIServerMetrics(raw), nil
}

// histogram accumulates cumulative bucket counts keyed by upper bound.
type histogram struct {
	buckets map[float64]float64
	count   float64
}

func (h *histogram) add(le float64, v float64) {
	if h.buckets == nil {
		h.buckets = map[float64]float64{}
	}
	h.buckets[le] += v
	if math.IsInf(le, 1) {
		h.count += v
	}
}

// quantile returns the linear-interpolated quantile (seconds) of a cumulative
// Prometheus histogram, the same way promql's histogram_quantile does.
func (h *histogram) quantile(q float64) float64 {
	if h.count == 0 || len(h.buckets) == 0 {
		return 0
	}
	bounds := make([]float64, 0, len(h.buckets))
	for le := range h.buckets {
		bounds = append(bounds, le)
	}
	sort.Float64s(bounds)
	rank := q * h.count
	prevBound, prevCount := 0.0, 0.0
	for _, b := range bounds {
		cnt := h.buckets[b]
		if cnt >= rank {
			if math.IsInf(b, 1) {
				return prevBound
			}
			if cnt == prevCount {
				return b
			}
			return prevBound + (b-prevBound)*((rank-prevCount)/(cnt-prevCount))
		}
		prevBound, prevCount = b, cnt
	}
	return prevBound
}

// parseAPIServerMetrics reads the Prometheus text format for the families we
// care about. Hand-rolled (no prometheus client dependency): the format is
// stable and we only need `_bucket`, plus a request counter for the 5xx rate.
func parseAPIServerMetrics(raw []byte) *APIServer {
	all := &histogram{}
	byVerb := map[string]*histogram{}
	etcd := &histogram{}
	var reqTotal, req5xx float64

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name, labels, value, ok := parseSample(line)
		if !ok {
			continue
		}
		switch name {
		case "apiserver_request_duration_seconds_bucket":
			// Skip WATCH (long-lived by design) and non-resource noise.
			if labels["verb"] == "WATCH" || labels["verb"] == "CONNECT" {
				continue
			}
			le, err := strconv.ParseFloat(labels["le"], 64)
			if err != nil {
				continue
			}
			all.add(le, value)
			verb := labels["verb"]
			if verb == "" {
				verb = "other"
			}
			h := byVerb[verb]
			if h == nil {
				h = &histogram{}
				byVerb[verb] = h
			}
			h.add(le, value)
		case "etcd_request_duration_seconds_bucket":
			if le, err := strconv.ParseFloat(labels["le"], 64); err == nil {
				etcd.add(le, value)
			}
		case "apiserver_request_total":
			reqTotal += value
			if strings.HasPrefix(labels["code"], "5") {
				req5xx += value
			}
		}
	}

	out := &APIServer{
		RequestP50Ms: ms(all.quantile(0.5)),
		RequestP99Ms: ms(all.quantile(0.99)),
		ByVerb:       map[string]Latency{},
	}
	for verb, h := range byVerb {
		out.ByVerb[verb] = Latency{P50Ms: ms(h.quantile(0.5)), P99Ms: ms(h.quantile(0.99))}
	}
	if etcd.count > 0 {
		out.EtcdVisible = true
		out.EtcdP99Ms = ms(etcd.quantile(0.99))
	}
	if reqTotal > 0 {
		out.Errors5xxPct = float64(int(req5xx/reqTotal*1000+0.5)) / 10
	}
	return out
}

func ms(seconds float64) float64 { return float64(int(seconds*1000*10+0.5)) / 10 }

// parseSample parses `name{a="b",c="d"} 12.5` (timestamp suffix tolerated).
func parseSample(line string) (name string, labels map[string]string, value float64, ok bool) {
	labels = map[string]string{}
	brace := strings.IndexByte(line, '{')
	var rest string
	if brace >= 0 {
		name = line[:brace]
		end := strings.IndexByte(line, '}')
		if end < brace {
			return "", nil, 0, false
		}
		for _, kv := range splitLabels(line[brace+1 : end]) {
			eq := strings.IndexByte(kv, '=')
			if eq < 0 {
				continue
			}
			labels[strings.TrimSpace(kv[:eq])] = strings.Trim(strings.TrimSpace(kv[eq+1:]), `"`)
		}
		rest = strings.TrimSpace(line[end+1:])
	} else {
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			return "", nil, 0, false
		}
		name = line[:sp]
		rest = strings.TrimSpace(line[sp+1:])
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", nil, 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "", nil, 0, false
	}
	return name, labels, v, true
}

// splitLabels splits on commas outside quotes.
func splitLabels(s string) []string {
	var out []string
	inQ := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			if i == 0 || s[i-1] != '\\' {
				inQ = !inQ
			}
		case ',':
			if !inQ {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
