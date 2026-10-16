package reqsign

import (
	"net/http"
	"testing"
	"time"
)

// Pinned against api/src/lib/hmac.test.ts ("v2 pins the exact bytes
// ts + \"\\n\" + body"): same key, timestamp and body on both sides.
const (
	pinKey  = "test-secret"
	pinTs   = "1700000000"
	pinBody = `{"a":1}`
	pinSig  = "e916cfe61f9f58fc65626a55fa4ad82d03aab12f68e6e931b3533e1b92fc0e08"
	// The legacy body-only signature of the same body, to prove the
	// timestamp really is bound into v2.
	legacySig = "179bf20a8b9040a32368814a68b0dc270823b5968498e0a73796c4202708ed8d"
)

func TestSignPinnedVector(t *testing.T) {
	if got := Sign(pinKey, pinTs, []byte(pinBody)); got != pinSig {
		t.Fatalf("Sign = %s, want %s", got, pinSig)
	}
	if got := Sign(pinKey, pinTs, []byte(pinBody)); got == legacySig {
		t.Fatal("v2 signature must differ from the body-only legacy signature")
	}
	if Sign(pinKey, "1700000001", []byte(pinBody)) == pinSig {
		t.Fatal("changing the timestamp must change the signature")
	}
}

func TestApplyAtSetsAllHeaders(t *testing.T) {
	h := http.Header{}
	ApplyAt(h, pinKey, []byte(pinBody), time.Unix(1700000000, 0), "0123456789abcdef0123456789abcdef")
	want := map[string]string{
		"X-Timestamp":         pinTs,
		"X-Nonce":             "0123456789abcdef0123456789abcdef",
		"X-Signature-Version": "2",
		"X-Signature":         pinSig,
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestApplyUsesWallClockAndFreshNonce(t *testing.T) {
	a, b := http.Header{}, http.Header{}
	before := time.Now().Unix()
	Apply(a, pinKey, []byte(pinBody))
	Apply(b, pinKey, []byte(pinBody))
	if a.Get("X-Nonce") == b.Get("X-Nonce") {
		t.Fatal("two requests must not share a nonce")
	}
	if len(a.Get("X-Nonce")) != 32 {
		t.Fatalf("nonce should be 16 bytes hex, got %q", a.Get("X-Nonce"))
	}
	ts := a.Get("X-Timestamp")
	var n int64
	for _, c := range ts {
		if c < '0' || c > '9' {
			t.Fatalf("timestamp must be decimal unix seconds, got %q", ts)
		}
		n = n*10 + int64(c-'0')
	}
	if n < before || n > time.Now().Unix() {
		t.Fatalf("timestamp %d not from the wall clock (now %d)", n, before)
	}
	if a.Get("X-Signature") != Sign(pinKey, ts, []byte(pinBody)) {
		t.Fatal("signature does not cover the X-Timestamp that was sent")
	}
}

func TestIsClockSkew(t *testing.T) {
	if !IsClockSkew(401, []byte(`{"error":"Request timestamp out of range"}`)) {
		t.Fatal("expected skew")
	}
	if IsClockSkew(401, []byte(`{"error":"Invalid signature"}`)) {
		t.Fatal("bad signature is not skew")
	}
	if IsClockSkew(200, []byte(`timestamp out of range`)) {
		t.Fatal("only a 401 counts")
	}
	if !WarnClockSkew(401, []byte(`{"error":"Request timestamp out of range"}`), "heartbeat") {
		t.Fatal("WarnClockSkew should report true on skew")
	}
	if WarnClockSkew(401, []byte(`{"error":"Invalid signature"}`), "heartbeat") {
		t.Fatal("WarnClockSkew should report false otherwise")
	}
}
