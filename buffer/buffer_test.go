package buffer

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestBuffer(t *testing.T) *Buffer {
	t.Helper()
	b, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open buffer: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func TestCursorRoundTrip(t *testing.T) {
	b := newTestBuffer(t)

	off, size, err := b.Cursor("/var/log/x")
	if err != nil || off != 0 || size != 0 {
		t.Fatalf("unseen cursor = (%d,%d,%v), want (0,0,nil)", off, size, err)
	}

	if err := b.SetCursor("/var/log/x", 1234, 2048); err != nil {
		t.Fatal(err)
	}
	off, size, err = b.Cursor("/var/log/x")
	if err != nil || off != 1234 || size != 2048 {
		t.Fatalf("cursor = (%d,%d,%v), want (1234,2048,nil)", off, size, err)
	}

	// Upsert overwrites.
	if err := b.SetCursor("/var/log/x", 5000, 6000); err != nil {
		t.Fatal(err)
	}
	off, _, _ = b.Cursor("/var/log/x")
	if off != 5000 {
		t.Errorf("after upsert offset = %d, want 5000", off)
	}
}

func TestSeenHashes(t *testing.T) {
	b := newTestBuffer(t)

	if seen, _ := b.Seen("abc"); seen {
		t.Error("hash should not be seen yet")
	}
	if err := b.MarkSeen([]string{"abc", "def"}); err != nil {
		t.Fatal(err)
	}
	if seen, _ := b.Seen("abc"); !seen {
		t.Error("abc should be seen after MarkSeen")
	}
	// Marking again must not error (idempotent).
	if err := b.MarkSeen([]string{"abc"}); err != nil {
		t.Errorf("re-mark errored: %v", err)
	}
	// Empty slice is a no-op.
	if err := b.MarkSeen(nil); err != nil {
		t.Errorf("empty mark errored: %v", err)
	}
}

// cursors for paths not updated within the window are pruned.
func TestPruneCursors(t *testing.T) {
	b := newTestBuffer(t)
	if err := b.SetCursor("/var/log/active", 10, 10); err != nil {
		t.Fatal(err)
	}
	// Backdate a "rotated" path's updated_at to 8 days ago.
	if _, err := b.db.Exec("INSERT INTO file_cursors (path, offset, size, updated_at) VALUES (?, ?, ?, ?)",
		"/var/log/access.log.3.gz", 5, 5, time.Now().Add(-8*24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := b.PruneCursors(7 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	// Stale one gone, active one kept.
	if off, _, _ := b.Cursor("/var/log/access.log.3.gz"); off != 0 {
		t.Errorf("stale cursor should be pruned, got offset %d", off)
	}
	if off, _, _ := b.Cursor("/var/log/active"); off != 10 {
		t.Errorf("active cursor should survive, got offset %d", off)
	}
}

// failed heartbeats are buffered oldest-first, capped, and drainable.
func TestPendingHeartbeats(t *testing.T) {
	b := newTestBuffer(t)
	// Enqueue 5 but cap at 3 → only the 3 newest survive.
	for i := 0; i < 5; i++ {
		if err := b.EnqueueHeartbeat([]byte{byte('a' + i)}, 3); err != nil {
			t.Fatal(err)
		}
	}
	pend, err := b.PendingHeartbeats(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pend) != 3 {
		t.Fatalf("expected 3 buffered (capped), got %d", len(pend))
	}
	// Oldest-first and the two oldest ('a','b') were dropped by the cap.
	if string(pend[0].Payload) != "c" || string(pend[2].Payload) != "e" {
		t.Errorf("wrong order/contents: %q..%q", pend[0].Payload, pend[2].Payload)
	}
	// Deleting one drops it from the queue.
	if err := b.DeleteHeartbeat(pend[0].ID); err != nil {
		t.Fatal(err)
	}
	if pend2, _ := b.PendingHeartbeats(10); len(pend2) != 2 {
		t.Errorf("after delete expected 2, got %d", len(pend2))
	}
}
