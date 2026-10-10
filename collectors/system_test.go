package collectors

import (
	"context"
	"testing"
	"time"
)

func TestSystemCollector_Collect(t *testing.T) {
	c := NewSystemCollector()
	if c.Name() != "system" {
		t.Fatalf("expected name 'system', got %q", c.Name())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	info, ok := out.(*SystemInfo)
	if !ok {
		t.Fatalf("expected *SystemInfo, got %T", out)
	}

	if info.Hostname == "" {
		t.Error("hostname should not be empty")
	}
	if info.Arch == "" {
		t.Error("arch should not be empty")
	}
	if info.CPUCores < 1 {
		t.Errorf("expected at least 1 CPU core, got %d", info.CPUCores)
	}
	if info.MemTotal == 0 {
		t.Error("mem_total should be greater than zero")
	}
}

func TestRegistry_CollectAll(t *testing.T) {
	reg := NewRegistry([]Collector{NewSystemCollector()})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload, err := reg.CollectAll(ctx)
	if err != nil {
		t.Fatalf("CollectAll returned error: %v", err)
	}
	if _, ok := payload.Data["system"]; !ok {
		t.Error("expected 'system' key in payload data")
	}
}
