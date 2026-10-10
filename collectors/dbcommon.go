package collectors

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Shared helpers for the datastore collectors (mysql.go, postgres.go, redis.go).
//
// Privacy rule: query text shipped in a snapshot is ALWAYS normalized first —
// string and numeric literals are replaced with `?` so customer data (emails,
// ids, tokens embedded in WHERE clauses) never leaves the box. Only the query
// *shape* is reported, which is all a slow-query recommendation needs.

// RunningQuery is one in-flight statement that has been running longer than
// the collector's "long" threshold (5 s). Query text is normalized.
type RunningQuery struct {
	Seconds int64  `json:"seconds"`
	State   string `json:"state,omitempty"`
	Query   string `json:"query"`
}

// SlowQueryPattern is an aggregated slow-query shape: how often it ran and how
// long it took, from the MySQL slow log or pg_stat_statements.
type SlowQueryPattern struct {
	Pattern     string  `json:"pattern"`
	Count       int64   `json:"count"`
	AvgSeconds  float64 `json:"avg_seconds"`
	MaxSeconds  float64 `json:"max_seconds,omitempty"`
	TotalSecs   float64 `json:"total_seconds"`
	RowsExamAvg int64   `json:"rows_examined_avg,omitempty"`
}

const maxQueryTextLen = 240

var (
	sqlStringLitRe = regexp.MustCompile(`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`)
	sqlNumLitRe    = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	sqlInListRe    = regexp.MustCompile(`(?i)\bIN\s*\((?:\s*\?\s*,?)+\)`)
	sqlValuesRe    = regexp.MustCompile(`(?i)\bVALUES\s*\((?:[^()]*)\)(?:\s*,\s*\([^()]*\))*`)
	sqlSpaceRe     = regexp.MustCompile(`\s+`)
)

// normalizeQuery strips literals from a SQL statement so it can be grouped
// and safely shipped: 'foo' → ?, 42 → ?, IN (?, ?, ?) → IN (?), whitespace
// collapsed, and the result truncated to maxQueryTextLen.
func normalizeQuery(q string) string {
	q = sqlStringLitRe.ReplaceAllString(q, "?")
	q = sqlNumLitRe.ReplaceAllString(q, "?")
	q = sqlValuesRe.ReplaceAllString(q, "VALUES (?)")
	q = sqlInListRe.ReplaceAllString(q, "IN (?)")
	q = strings.TrimSpace(sqlSpaceRe.ReplaceAllString(q, " "))
	q = strings.TrimSuffix(q, ";")
	if len(q) > maxQueryTextLen {
		q = q[:maxQueryTextLen] + "…"
	}
	return q
}

// containerRef is one running Docker container (name + image) for discovery.
type containerRef struct {
	Name  string
	Image string
}

// listContainers returns running containers, or nil when Docker is absent.
func listContainers(ctx context.Context) []containerRef {
	if !hasBinary("docker") {
		return nil
	}
	out, err := runCmdTimeout(ctx, 4*time.Second, "docker", "ps", "--format", "{{.Names}}\t{{.Image}}")
	if err != nil {
		return nil
	}
	var refs []containerRef
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.SplitN(line, "\t", 2)
		name := strings.TrimSpace(f[0])
		if name == "" {
			continue
		}
		ref := containerRef{Name: name}
		if len(f) > 1 {
			ref.Image = strings.TrimSpace(f[1])
		}
		refs = append(refs, ref)
	}
	return refs
}
