package executor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A long command no longer blocks the poll loop: polls keep coming (and say
// `busy`), commands still run one at a time in the order they arrived.
func TestLongCommandDoesNotBlockPolling(t *testing.T) {
	old := commandSigningPublicKeyHex
	commandSigningPublicKeyHex = "" // unsigned test commands
	defer func() { commandSigningPublicKeyHex = old }()

	exp := time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
	var mu sync.Mutex
	polls, busyPolls := 0, 0
	var finished []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/commands/poll"):
			polls++
			var req map[string]interface{}
			_ = json.Unmarshal(body, &req)
			if req["busy"] == true {
				busyPolls++
			}
			if polls == 1 {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"commands": []map[string]interface{}{
					{"id": "slow", "command": "sleep 0.6", "timeout_seconds": 5, "expires_at": exp},
					{"id": "fast", "command": "true", "timeout_seconds": 5, "expires_at": exp},
				}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"commands": []interface{}{}})
		case strings.HasSuffix(r.URL.Path, "/result"):
			parts := strings.Split(r.URL.Path, "/")
			finished = append(finished, parts[len(parts)-2])
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	e := New(srv.URL, "agent-1", "secret", 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(finished)
		mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(finished) != 2 || finished[0] != "slow" || finished[1] != "fast" {
		t.Fatalf("commands must finish in order, got %v", finished)
	}
	// ~600 ms of sleep at a 50 ms cadence: polling carried on, flagged busy.
	if busyPolls < 3 {
		t.Fatalf("expected several busy polls while the long command ran, got %d (of %d polls)", busyPolls, polls)
	}
}
