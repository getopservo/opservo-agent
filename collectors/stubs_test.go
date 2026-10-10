package collectors

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func portFromURL(t *testing.T, url string) uint32 {
	t.Helper()
	i := strings.LastIndex(url, ":")
	if i < 0 {
		t.Fatalf("no port in url %q", url)
	}
	p, err := strconv.Atoi(url[i+1:])
	if err != nil {
		t.Fatalf("bad port in url %q: %v", url, err)
	}
	return uint32(p)
}

// probeHTTPStatuses should return the real status of a serving loopback port,
// skip well-known non-HTTP (database) ports, and skip non-tcp entries.
func TestProbeHTTPStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // 502-ish: listening but broken
	}))
	defer srv.Close()
	port := portFromURL(t, srv.URL)

	got := probeHTTPStatuses([]ListeningPort{
		{Port: port, Protocol: "tcp"},
		{Port: 3306, Protocol: "tcp"}, // MySQL — in nonHTTPPorts, must be skipped
		{Port: port, Protocol: "udp"}, // non-tcp, must be skipped
	})

	if got[port] != http.StatusServiceUnavailable {
		t.Errorf("serving port: want %d, got %d", http.StatusServiceUnavailable, got[port])
	}
	if _, ok := got[3306]; ok {
		t.Errorf("database port 3306 must not be probed")
	}
}

// A port with nothing listening yields no entry (connection refused, not a hang).
func TestProbeHTTPStatuses_deadPort(t *testing.T) {
	got := probeHTTPStatuses([]ListeningPort{{Port: 9, Protocol: "tcp"}})
	if _, ok := got[9]; ok {
		t.Errorf("dead port should have no status, got %v", got)
	}
}

// applyCachedHTTPStatus fills from the last completed probe and leaves
// not-yet-probed ports at 0.
func TestApplyCachedHTTPStatus(t *testing.T) {
	httpStatusMu.Lock()
	prev := httpStatusCache
	httpStatusCache = map[uint32]int{8080: 200}
	httpStatusMu.Unlock()
	t.Cleanup(func() {
		httpStatusMu.Lock()
		httpStatusCache = prev
		httpStatusMu.Unlock()
	})

	ports := []ListeningPort{{Port: 8080, Protocol: "tcp"}, {Port: 9090, Protocol: "tcp"}}
	applyCachedHTTPStatus(ports)

	if ports[0].HTTPStatus != 200 {
		t.Errorf("cached port 8080: want 200, got %d", ports[0].HTTPStatus)
	}
	if ports[1].HTTPStatus != 0 {
		t.Errorf("uncached port 9090: want 0, got %d", ports[1].HTTPStatus)
	}
}

// The background refresh serves the previous cache immediately (no blocking) and
// populates the cache for the next call; a second refresh while one is "running"
// is a no-op (single-flight).
func TestRefreshHTTPStatusInBackground(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	port := portFromURL(t, srv.URL)

	httpStatusMu.Lock()
	prev := httpStatusCache
	httpStatusCache = map[uint32]int{}
	httpProbeRunning = false
	httpStatusMu.Unlock()
	t.Cleanup(func() {
		httpStatusMu.Lock()
		httpStatusCache = prev
		httpProbeRunning = false
		httpStatusMu.Unlock()
	})

	ports := []ListeningPort{{Port: port, Protocol: "tcp"}}
	refreshHTTPStatusInBackground(ports)

	// Poll for the background probe to land in the cache (bounded).
	var got int
	for i := 0; i < 100; i++ {
		httpStatusMu.Lock()
		got = httpStatusCache[port]
		httpStatusMu.Unlock()
		if got != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got != http.StatusOK {
		t.Errorf("background probe should have cached %d, got %d", http.StatusOK, got)
	}
}
