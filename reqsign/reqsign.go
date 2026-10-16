// Package reqsign signs the agent's HMAC-authenticated HTTP requests
// (heartbeat, command poll / progress / result) with timestamp and nonce
// binding, so a captured request cannot be replayed against the API.
//
// Wire format ("v2"):
//
//	X-Timestamp:         <unix seconds, decimal>
//	X-Nonce:             <16 random bytes, hex>
//	X-Signature-Version: 2
//	X-Signature:         hex(HMAC-SHA256(secret, X-Timestamp + "\n" + body))
//
// The API accepts the timestamp within ±5 minutes of its own clock and
// refuses a reused (agent, nonce) pair inside that window. The exact bytes
// signed are pinned on both sides by reqsign_test.go and the API's
// lib/hmac.test.ts — change one, change the other.
//
// The live-terminal dial (shell/session.go) keeps its own sid+ts signature;
// it already carries a timestamp and is verified separately.
package reqsign

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is the value sent in X-Signature-Version.
const Version = "2"

// Sign returns hex(HMAC-SHA256(secret, ts + "\n" + body)).
func Sign(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Apply sets the v2 authentication headers on h for body, stamped with the
// current wall clock (time.Now — the only source the API's skew check can be
// reconciled against).
func Apply(h http.Header, secret string, body []byte) {
	ApplyAt(h, secret, body, time.Now(), newNonce())
}

// ApplyAt is Apply with an explicit clock and nonce, for tests.
func ApplyAt(h http.Header, secret string, body []byte, now time.Time, nonce string) {
	ts := strconv.FormatInt(now.Unix(), 10)
	h.Set("X-Timestamp", ts)
	h.Set("X-Nonce", nonce)
	h.Set("X-Signature-Version", Version)
	h.Set("X-Signature", Sign(secret, ts, body))
}

func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is a broken host; fall back to the clock so the
		// request still carries a unique-enough nonce rather than none.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// skewMarker is the error text the API returns when X-Timestamp is outside
// its accepted window.
const skewMarker = "timestamp out of range"

// IsClockSkew reports whether a 401 response body says the API rejected our
// timestamp — i.e. this box's clock is off, not its credentials.
func IsClockSkew(status int, body []byte) bool {
	return status == http.StatusUnauthorized && strings.Contains(strings.ToLower(string(body)), skewMarker)
}

var (
	skewMu       sync.Mutex
	skewLastWarn time.Time
)

// skewWarnEvery throttles the NTP hint: the executor polls every few seconds,
// and one line every 10 minutes is enough to find the cause in the journal.
const skewWarnEvery = 10 * time.Minute

// WarnClockSkew logs a clear hint when the API refused our timestamp. The
// caller keeps its normal retry cadence — a wrong clock is fixed by NTP, not
// by polling faster.
func WarnClockSkew(status int, body []byte, what string) bool {
	if !IsClockSkew(status, body) {
		return false
	}
	skewMu.Lock()
	defer skewMu.Unlock()
	if time.Since(skewLastWarn) < skewWarnEvery {
		return true
	}
	skewLastWarn = time.Now()
	slog.Error("API rejected request: this server's clock is more than 5 minutes off",
		"request", what,
		"hint", "sync the clock with NTP (e.g. `sudo timedatectl set-ntp true` or `sudo chronyc makestep`), then the agent recovers on its own")
	return true
}
