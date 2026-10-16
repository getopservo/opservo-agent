package collectors

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTailBufferKeepsNewestWholeLines(t *testing.T) {
	tb := &tailBuffer{max: 64}
	for i := 0; i < 200; i++ {
		_, _ = tb.Write([]byte("line-" + strings.Repeat("x", 10) + "-" + string(rune('a'+i%26)) + "\n"))
	}
	out := string(tb.Bytes())
	if len(out) > 64 {
		t.Fatalf("kept %d bytes, cap is 64", len(out))
	}
	if !strings.HasSuffix(out, "-r\n") { // line 199 → 'a'+199%26 = 'r'
		t.Fatalf("newest line missing: %q", out)
	}
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if !strings.HasPrefix(l, "line-") {
			t.Fatalf("partial leading line kept: %q", out)
		}
	}
	small := &tailBuffer{max: 64}
	_, _ = small.Write([]byte("a\nb\n"))
	if string(small.Bytes()) != "a\nb\n" {
		t.Fatalf("output under the cap must be untouched, got %q", small.Bytes())
	}
}

func TestRunCmdTailBoundsOutput(t *testing.T) {
	out, err := runCmdTail(context.Background(), 5*time.Second, 1024, "sh", "-c", "i=0; while [ $i -lt 5000 ]; do echo line-$i; i=$((i+1)); done")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 1024 || !strings.HasSuffix(string(out), "line-4999\n") {
		t.Fatalf("want ≤1024 bytes ending with the last line, got %d bytes ending %q", len(out), string(out[len(out)-12:]))
	}
}
