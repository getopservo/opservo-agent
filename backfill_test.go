package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/softuvo-ai/opservo-agent/buffer"
	"github.com/softuvo-ai/opservo-agent/sender"
)

// A recovering agent must replay at most maxBackfillPerTick buffered
// heartbeats per successful send: replaying the whole backlog pushed the
// agent over the API's per-minute limit and the backlog never drained.
func TestFlushPendingReplaysOnePerTick(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	buf, err := buffer.Open(filepath.Join(t.TempDir(), "buf.db"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := buf.EnqueueHeartbeat([]byte(`{"n":`+string(rune('0'+i))+`}`), maxPendingHeartbeats); err != nil {
			t.Fatal(err)
		}
	}
	s := sender.New(srv.URL, "agent-1", "secret", true)

	flushPending(context.Background(), s, buf)

	if got := atomic.LoadInt32(&hits); got != int32(maxBackfillPerTick) {
		t.Fatalf("replayed %d heartbeats in one tick, want %d", got, maxBackfillPerTick)
	}
	rest, err := buf.PendingHeartbeats(maxPendingHeartbeats)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 3-maxBackfillPerTick {
		t.Fatalf("%d heartbeats still pending, want %d", len(rest), 3-maxBackfillPerTick)
	}
}

// A 429 must be recognised so the live heartbeat is NOT buffered for replay
// (replaying a rate-limited send only trips the limit again); other
// failures are still buffered.
func TestIsRateLimited(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   bool
	}{
		{http.StatusTooManyRequests, true},
		{http.StatusNotFound, false},
		{http.StatusBadGateway, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
		}))
		s := sender.New(srv.URL, "agent-1", "secret", true)
		_, err := s.SendRaw(context.Background(), []byte(`{}`))
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: expected an error", tc.status)
		}
		if got := isRateLimited(err); got != tc.want {
			t.Errorf("status %d: isRateLimited=%v, want %v (err=%v)", tc.status, got, tc.want, err)
		}
	}
	if isRateLimited(context.Canceled) {
		t.Error("non-status error reported as rate-limited")
	}
}
