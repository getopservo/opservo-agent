package collectors

import "testing"

func TestParseDockerSize(t *testing.T) {
	mib := func(n float64) int64 { return int64(n * 1024 * 1024) }
	cases := map[string]int64{
		"0B":       0,
		"4kB":      4000,
		"550.6MiB": mib(550.6),
		"1.2GB":    1_200_000_000,
		"2GiB":     2 * 1024 * 1024 * 1024,
		"":         0,
	}
	for in, want := range cases {
		if got := parseDockerSize(in); got != want {
			t.Errorf("parseDockerSize(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseDockerStats(t *testing.T) {
	out := "LibreChat\t1.32%\t550.6MiB / 7.6GiB\t7.05%\t1.2GB / 800MB\n" +
		"redis\t0.10%\t10MiB / 7.6GiB\t0.13%\t5MB / 4MB\n" +
		"\t\t\t\t" // junk line ignored
	rows := parseDockerStats(out)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Name != "LibreChat" || rows[0].CPUPercent != 1.32 || rows[0].MemPercent != 7.05 {
		t.Fatalf("row0 parse wrong: %+v", rows[0])
	}
	m := 550.6
	if rows[0].MemBytes != int64(m*1024*1024) {
		t.Fatalf("mem bytes wrong: %d", rows[0].MemBytes)
	}
	if rows[0].NetRxBytes != 1_200_000_000 || rows[0].NetTxBytes != 800_000_000 {
		t.Fatalf("net wrong: rx=%d tx=%d", rows[0].NetRxBytes, rows[0].NetTxBytes)
	}
}
