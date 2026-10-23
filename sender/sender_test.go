package sender

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getopservo/opservo-agent/reqsign"
)

// The API (lib/hmac.ts) verifies exactly these headers over exactly the bytes
// sent, so the test re-computes the v2 signature from what arrived.
func TestSendRawSignsTheExactBodyWithV2Headers(t *testing.T) {
	body := []byte(`{"system":{"hostname":"web-1"}}`)
	var got *http.Request
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	ack, err := New(srv.URL, "agent-123", "s3cret", false).SendRaw(context.Background(), body)
	if err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	if string(ack) != `{"ok":true}` {
		t.Errorf("ack = %q, want the response body", ack)
	}
	if got.Method != http.MethodPost || got.URL.Path != "/api/v1/agents/agent-123/heartbeat" {
		t.Errorf("request = %s %s", got.Method, got.URL.Path)
	}
	if string(gotBody) != string(body) {
		t.Errorf("body = %q, want the bytes passed in", gotBody)
	}
	h := got.Header
	if h.Get("Content-Type") != "application/json" || h.Get("X-Agent-ID") != "agent-123" {
		t.Errorf("content-type/agent-id headers = %q / %q", h.Get("Content-Type"), h.Get("X-Agent-ID"))
	}
	if h.Get("X-Signature-Version") != reqsign.Version || len(h.Get("X-Nonce")) != 32 {
		t.Errorf("version/nonce headers = %q / %q", h.Get("X-Signature-Version"), h.Get("X-Nonce"))
	}
	if want := reqsign.Sign("s3cret", h.Get("X-Timestamp"), body); h.Get("X-Signature") != want {
		t.Errorf("X-Signature = %q, want %q", h.Get("X-Signature"), want)
	}
}

func TestSendRawAccepts202(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "a", "k", false).SendRaw(context.Background(), []byte(`{}`)); err != nil {
		t.Fatalf("202 should be a successful send, got %v", err)
	}
}

// The main loop must not buffer a 429 for replay (it only re-trips the limit),
// so the code has to come back as a StatusError it can branch on.
func TestSendRawReturnsStatusErrorForNon2xx(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusUnauthorized, http.StatusNotFound, http.StatusInternalServerError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":"timestamp out of range"}`))
		}))
		ack, err := New(srv.URL, "a", "k", false).SendRaw(context.Background(), []byte(`{}`))
		srv.Close()

		var se *StatusError
		if !errors.As(err, &se) || se.Code != code {
			t.Errorf("status %d: err = %v, want *StatusError{%d}", code, err, code)
		}
		if ack != nil {
			t.Errorf("status %d: ack = %q, want nil", code, ack)
		}
	}
}

func TestSendRawCapsTheAckBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 300*1024)))
	}))
	defer srv.Close()

	ack, err := New(srv.URL, "a", "k", false).SendRaw(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("SendRaw: %v", err)
	}
	if len(ack) != 256*1024 {
		t.Errorf("ack length = %d, want the 256 KiB cap", len(ack))
	}
}

func TestSendRawReportsAnUnreachableAPI(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	_, err := New(url, "a", "k", false).SendRaw(context.Background(), []byte(`{}`))
	var se *StatusError
	if err == nil || errors.As(err, &se) {
		t.Fatalf("err = %v, want a transport error (not a StatusError)", err)
	}
}

func TestRegisterKindSendsFieldsAndDecodesTheKey(t *testing.T) {
	var fields map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agents/register" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		fields = nil
		_ = json.NewDecoder(r.Body).Decode(&fields)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"agent_id":"id-1","secret_key":"key-1"}`))
	}))
	defer srv.Close()

	id, key, err := RegisterKind(srv.URL, "src-abc", false, "ipk_tok", "mid-1", "web-1", "")
	if err != nil || id != "id-1" || key != "key-1" {
		t.Fatalf("RegisterKind = %q, %q, %v", id, key, err)
	}
	want := map[string]string{"hostname": "web-1", "agent_version": "src-abc", "machine_id": "mid-1", "enrollment_token": "ipk_tok"}
	if len(fields) != len(want) {
		t.Errorf("fields = %v, want %v (no kind for a Linux agent)", fields, want)
	}
	for k, v := range want {
		if fields[k] != v {
			t.Errorf("fields[%q] = %q, want %q", k, fields[k], v)
		}
	}

	if _, _, err := RegisterKind(srv.URL, "v", false, "", "m", "cluster-1", "kubernetes"); err != nil {
		t.Fatalf("RegisterKind kubernetes: %v", err)
	}
	if fields["kind"] != "kubernetes" {
		t.Errorf("kind = %q, want kubernetes", fields["kind"])
	}
	if _, ok := fields["enrollment_token"]; ok {
		t.Errorf("an empty enrollment token must not be sent")
	}
}

func TestRegisterKindFailsOnNon201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	if _, _, err := RegisterKind(srv.URL, "v", false, "bad", "m", "h", ""); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want a status 403 error", err)
	}
}
