// Package buffer provides a small SQLite-backed store the agent uses to
// remember what it has already shipped: a byte-offset cursor per log file and
// a set of recently-seen content hashes for command-based sources (docker,
// journalctl) that have no stable file offset. This lets the log collector
// avoid sending the same line twice across heartbeats.
package buffer

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGO)
)

type Buffer struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite buffer at path and ensures the
// schema exists.
func Open(path string) (*Buffer, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open buffer: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: serialize access, avoid "database is locked"

	schema := `
	CREATE TABLE IF NOT EXISTS file_cursors (
		path       TEXT PRIMARY KEY,
		offset     INTEGER NOT NULL,
		size       INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS seen_hashes (
		hash    TEXT PRIMARY KEY,
		seen_at INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS pending_heartbeats (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		payload      BLOB NOT NULL,
		collected_at INTEGER NOT NULL
	);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init buffer schema: %w", err)
	}
	return &Buffer{db: db}, nil
}

func (b *Buffer) Close() error { return b.db.Close() }

// Cursor returns the stored read offset and last-known size for a file. A file
// the buffer has never seen returns (0, 0, nil).
func (b *Buffer) Cursor(path string) (offset int64, size int64, err error) {
	row := b.db.QueryRow("SELECT offset, size FROM file_cursors WHERE path = ?", path)
	switch err := row.Scan(&offset, &size); err {
	case nil:
		return offset, size, nil
	case sql.ErrNoRows:
		return 0, 0, nil
	default:
		return 0, 0, err
	}
}

// SetCursor records the read offset and size for a file.
func (b *Buffer) SetCursor(path string, offset, size int64) error {
	_, err := b.db.Exec(
		`INSERT INTO file_cursors (path, offset, size, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(path) DO UPDATE SET offset=excluded.offset, size=excluded.size, updated_at=excluded.updated_at`,
		path, offset, size, time.Now().Unix(),
	)
	return err
}

// Seen reports whether a content hash was recorded in a previous heartbeat.
func (b *Buffer) Seen(hash string) (bool, error) {
	var one int
	switch err := b.db.QueryRow("SELECT 1 FROM seen_hashes WHERE hash = ?", hash).Scan(&one); err {
	case nil:
		return true, nil
	case sql.ErrNoRows:
		return false, nil
	default:
		return false, err
	}
}

// MarkSeen records content hashes so they are not re-sent on the next heartbeat.
func (b *Buffer) MarkSeen(hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}
	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO seen_hashes (hash, seen_at) VALUES (?, ?) ON CONFLICT(hash) DO NOTHING`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	for _, h := range hashes {
		if _, err := stmt.Exec(h, now); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// PruneHashes deletes seen-hash records older than the given age to bound the
// buffer's growth.
func (b *Buffer) PruneHashes(olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan).Unix()
	_, err := b.db.Exec("DELETE FROM seen_hashes WHERE seen_at < ?", cutoff)
	return err
}

// PruneCursors deletes cursor rows for paths not updated within `olderThan`.
// SetCursor bumps updated_at for every active path each cycle, so log-rotated
// paths (access.log.1, .2.gz, …) that are no longer tailed age out — bounding
// the file_cursors table instead of growing forever.
func (b *Buffer) PruneCursors(olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan).Unix()
	_, err := b.db.Exec("DELETE FROM file_cursors WHERE updated_at < ?", cutoff)
	return err
}

// PendingHeartbeat is a buffered heartbeat awaiting retry.
type PendingHeartbeat struct {
	ID      int64
	Payload []byte
}

// EnqueueHeartbeat buffers a heartbeat payload that failed to send, keeping only
// the newest `max` rows so a long outage can't grow the buffer without bound.
func (b *Buffer) EnqueueHeartbeat(payload []byte, max int) error {
	if _, err := b.db.Exec("INSERT INTO pending_heartbeats (payload, collected_at) VALUES (?, ?)", payload, time.Now().Unix()); err != nil {
		return err
	}
	_, err := b.db.Exec(
		"DELETE FROM pending_heartbeats WHERE id NOT IN (SELECT id FROM pending_heartbeats ORDER BY id DESC LIMIT ?)", max)
	return err
}

// PendingHeartbeats returns buffered heartbeats oldest-first (up to limit), so a
// successful send can backfill the gaps left by an outage.
func (b *Buffer) PendingHeartbeats(limit int) ([]PendingHeartbeat, error) {
	rows, err := b.db.Query("SELECT id, payload FROM pending_heartbeats ORDER BY id ASC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingHeartbeat
	for rows.Next() {
		var p PendingHeartbeat
		if err := rows.Scan(&p.ID, &p.Payload); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteHeartbeat removes a buffered heartbeat once it has been flushed.
func (b *Buffer) DeleteHeartbeat(id int64) error {
	_, err := b.db.Exec("DELETE FROM pending_heartbeats WHERE id = ?", id)
	return err
}
