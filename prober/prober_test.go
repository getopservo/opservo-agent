package prober

import (
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSigningMessageFormat(t *testing.T) {
	// Pins the exact byte format shared with the TS signer
	// (the Opservo API's probeSigningMessage) — the mirror test
	// there asserts the same literal string.
	c := Check{ID: "mon-1", Kind: "tcp", Target: "db.internal:3306", TimeoutMs: 5000}
	got := signingMessage("agent-1", c)
	want := "probe\nmon-1\nagent-1\ntcp\ndb.internal:3306\n5000"
	if got != want {
		t.Fatalf("signing message drifted:\n got %q\nwant %q", got, want)
	}
}

func TestVerifySignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)
	c := Check{ID: "mon-1", Kind: "tcp", Target: "10.0.0.5:3306", TimeoutMs: 5000}
	c.Sig = hex.EncodeToString(ed25519.Sign(priv, []byte(signingMessage("agent-1", c))))

	if err := verifySignature(pubHex, "agent-1", c); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Bound to the agent: same check signed for agent-1 must fail for agent-2.
	if err := verifySignature(pubHex, "agent-2", c); err == nil {
		t.Fatal("signature for another agent accepted")
	}
	// Retargeted check must fail — this is the whole point.
	retargeted := c
	retargeted.Target = "10.0.0.99:22"
	if err := verifySignature(pubHex, "agent-1", retargeted); err == nil {
		t.Fatal("retargeted check accepted")
	}
	// Foreign (attacker) key must fail.
	_, evilPriv, _ := ed25519.GenerateKey(nil)
	evil := c
	evil.Sig = hex.EncodeToString(ed25519.Sign(evilPriv, []byte(signingMessage("agent-1", c))))
	if err := verifySignature(pubHex, "agent-1", evil); err == nil {
		t.Fatal("foreign-key signature accepted")
	}
	// Missing / malformed signatures fail closed.
	for _, sig := range []string{"", "not-hex", "abcd"} {
		bad := c
		bad.Sig = sig
		if err := verifySignature(pubHex, "agent-1", bad); err == nil {
			t.Fatalf("malformed signature %q accepted", sig)
		}
	}
	// Empty pubkey = verification disabled (rollout convention).
	unsigned := Check{ID: "m", Kind: "tcp", Target: "x:1", TimeoutMs: 1000}
	if err := verifySignature("", "agent-1", unsigned); err != nil {
		t.Fatalf("empty pubkey should disable verification: %v", err)
	}
}

func TestRunOne(t *testing.T) {
	// Up: a live local listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	r := runOne(Check{ID: "m1", Kind: "tcp", Target: ln.Addr().String(), TimeoutMs: 2000})
	if !r.Up {
		t.Fatalf("expected up for live listener, got error %q", r.Error)
	}
	// Down: a port nothing listens on (the listener's port after close would
	// race; use a reserved-but-closed one on localhost).
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()
	r = runOne(Check{ID: "m2", Kind: "tcp", Target: addr, TimeoutMs: 1000})
	if r.Up {
		t.Fatal("expected down for closed port")
	}
	if r.Error == "" {
		t.Fatal("down result should carry an error")
	}
}

func TestRunRejectsUnsignedWhenKeySet(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	p := &Prober{agentID: "agent-1", pubKey: hex.EncodeToString(pub)}
	p.Run([]Check{{ID: "m1", Kind: "tcp", Target: "127.0.0.1:1", TimeoutMs: 500}})
	// Run is async — poll Drain briefly.
	var results []Result
	for i := 0; i < 50; i++ {
		if results = p.Drain(); len(results) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Up || !strings.HasPrefix(results[0].Error, "rejected:") {
		t.Fatalf("unsigned check should be rejected, got %+v", results[0])
	}
}

func TestRunIsSingleFlightAndConcurrent(t *testing.T) {
	release := make(chan struct{})
	var inFlight, peak int32
	var mu sync.Mutex
	p := &Prober{agentID: "agent-1", dial: func(c Check) Result {
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		mu.Unlock()
		<-release
		mu.Lock()
		inFlight--
		mu.Unlock()
		return Result{ID: c.ID, Up: true}
	}}
	checks := []Check{{ID: "m1", Kind: "tcp", Target: "a:1"}, {ID: "m2", Kind: "tcp", Target: "b:1"}, {ID: "m3", Kind: "udp", Target: "c:1"}}
	if !p.Run(checks) {
		t.Fatal("first run should start")
	}
	// A heartbeat arriving while the first run is still dialing starts nothing.
	if p.Run([]Check{{ID: "late", Kind: "tcp", Target: "d:1"}}) {
		t.Fatal("second run must be skipped while one is in flight")
	}
	// Both dials are in flight at once (concurrent, not one after the other).
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := inFlight
		mu.Unlock()
		if n == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	var results []Result
	for i := 0; i < 100; i++ {
		if results = p.Drain(); len(results) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if peak != 2 {
		t.Fatalf("expected 2 concurrent dials, peak was %d", peak)
	}
	if len(results) != 3 || results[0].ID != "m1" || results[1].ID != "m2" || results[2].ID != "m3" || results[2].Up {
		t.Fatalf("results out of order or wrong: %+v", results)
	}
	for i := 0; i < 100 && p.running.Load(); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !p.Run(checks[:1]) {
		t.Fatal("a new run should start once the previous one finished")
	}
}
