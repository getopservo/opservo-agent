package collectors

import (
	"testing"
	"time"
)

func TestParseAccessWindow(t *testing.T) {
	now, _ := time.Parse(accessTimeLayout, "28/Jun/2026:12:05:00 +0000")
	log := `192.168.1.5 - - [28/Jun/2026:12:04:50 +0000] "GET /a HTTP/1.1" 200 1200 "-" "UA"
192.168.1.6 - - [28/Jun/2026:12:04:55 +0000] "POST /b HTTP/1.1" 500 80 "-" "UA"
192.168.1.7 - - [28/Jun/2026:12:04:59 +0000] "GET /c HTTP/1.1" 404 10 "-" "UA"
10.0.0.1 - - [28/Jun/2026:11:00:00 +0000] "GET /old HTTP/1.1" 200 5 "-" "UA"
garbage line that should be ignored`
	s := parseAccessWindow(log, now, 300)
	if s.Requests != 3 { // the 11:00 line is outside the 5-min window
		t.Fatalf("requests = %d, want 3", s.Requests)
	}
	if s.S2xx != 1 || s.S5xx != 1 || s.S4xx != 1 {
		t.Fatalf("class counts wrong: %+v", s)
	}
	if s.Bytes != 1200+80+10 {
		t.Fatalf("bytes = %d, want 1290", s.Bytes)
	}
}

func TestParseAccessWindowEmpty(t *testing.T) {
	now := time.Now()
	if s := parseAccessWindow("", now, 300); s.Requests != 0 {
		t.Fatalf("empty should yield 0 requests, got %d", s.Requests)
	}
}
