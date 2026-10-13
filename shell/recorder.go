package shell

import "unicode/utf8"

// maxLine bounds one recorded line; anything longer is cut (a paste of a
// whole file is not a "command").
const maxLine = 4096

// lineRecorder turns the keystrokes a person types into the lines they
// entered, for the session recording. It is fed ONLY input the caller judged
// recordable (session.go recordable: not a password prompt), so a password
// typed at a prompt with echo off never reaches it.
//
// It understands the editing a shell prompt does in practice: backspace,
// Ctrl-U (kill line), Ctrl-C (abandon line). Escape sequences (arrow keys,
// history recall, function keys) are dropped from the text — a line recalled
// with ↑ shows only what was typed after it, which is honest about what the
// recording can know.
type lineRecorder struct {
	buf []byte
	esc int // 0 = normal, 1 = after ESC, 2 = inside CSI (ESC [ … final byte)
}

// Feed consumes echoed input and returns any lines completed by Enter.
func (r *lineRecorder) Feed(p []byte) []string {
	var out []string
	for _, b := range p {
		switch r.esc {
		case 1:
			if b == '[' || b == 'O' {
				r.esc = 2
			} else {
				r.esc = 0
			}
			continue
		case 2:
			if b >= 0x40 && b <= 0x7e {
				r.esc = 0
			}
			continue
		}
		switch b {
		case 0x1b:
			r.esc = 1
		case '\r', '\n':
			if len(r.buf) > 0 {
				out = append(out, string(r.buf))
			}
			r.buf = r.buf[:0]
		case 0x7f, 0x08: // backspace: drop the last whole rune
			if len(r.buf) > 0 {
				_, size := utf8.DecodeLastRune(r.buf)
				r.buf = r.buf[:len(r.buf)-size]
			}
		case 0x15, 0x03: // Ctrl-U, Ctrl-C: the line is gone
			r.buf = r.buf[:0]
		default:
			if b >= 0x20 && len(r.buf) < maxLine {
				r.buf = append(r.buf, b)
			}
		}
	}
	return out
}

// Reset forgets a half-typed line (called when echo turns off, so a line
// started before a password prompt can't absorb anything after it).
func (r *lineRecorder) Reset() { r.buf = r.buf[:0]; r.esc = 0 }
