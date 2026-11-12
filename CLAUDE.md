# Opservo agent (Go) — conventions

Loaded only when working under `agent/`. Repo-wide rules (security, remote-action
locks, staging-first) stay in the root `CLAUDE.md`.

```go
// Package names: lowercase, single word
// Collector interface — every collector must implement this:
type Collector interface {
    Name() string
    Collect(ctx context.Context) (interface{}, error)
}

// Error handling: always wrap with context
if err != nil {
    return fmt.Errorf("system collector: failed to read cpu: %w", err)
}

// No global state. Pass dependencies explicitly.
// Tests required for every collector.
```
