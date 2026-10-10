package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeletedOpenBytes(t *testing.T) {
	// deletedOpenBytes() scans /proc/<pid>/fd for every running process, so we
	// can't isolate it to fixtures — instead hold real deleted fds open in this
	// test process (visible under /proc/self/fd, no root needed) and check the
	// totals moved by that much.
	dir := t.TempDir()
	before := deletedOpenBytes() // baseline BEFORE opening/deleting anything

	// A genuinely space-holding deleted file (the classic "rotated log still
	// held open by the writer" case): actual bytes written, blocks ≈ size.
	realPath := filepath.Join(dir, "real.log")
	realFile, err := os.Create(realPath)
	if err != nil {
		t.Fatal(err)
	}
	defer realFile.Close()
	const realSize = 4 * 1024 * 1024 // 4 MiB of real data
	if _, err := realFile.Write(make([]byte, realSize)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(realPath); err != nil {
		t.Fatal(err)
	}

	// fd still open (deleted), should now be counted close to its real size.
	after := deletedOpenBytes()
	if after < before {
		t.Fatalf("total should not shrink while the deleted fd is still held: before=%d after=%d", before, after)
	}
	gained := after - before
	if gained < realSize/2 || gained > realSize*2 {
		t.Errorf("a real 4 MiB deleted-but-open file should contribute roughly its real size, got %d bytes", gained)
	}

	// A sparse deleted file with a huge apparent size but near-zero real
	// blocks — the memfd/doublemapper false-positive case. Truncate() creates
	// a hole-punched sparse file: st.Size is huge, st.Blocks stays tiny.
	sparsePath := filepath.Join(dir, "sparse.bin")
	sparseFile, err := os.Create(sparsePath)
	if err != nil {
		t.Fatal(err)
	}
	defer sparseFile.Close()
	const sparseApparentSize = 2 * 1024 * 1024 * 1024 * 1024 // 2 TiB, all virtual
	if err := sparseFile.Truncate(sparseApparentSize); err != nil {
		t.Skipf("filesystem doesn't support sparse files large enough for this test: %v", err)
	}
	if err := os.Remove(sparsePath); err != nil {
		t.Fatal(err)
	}

	afterSparse := deletedOpenBytes()
	sparseContribution := afterSparse - after
	// A correct (st.Blocks-based) implementation should count this as ~0
	// (empty sparse file, no blocks allocated) — nowhere near the 2 TiB
	// apparent size a st.Size-based implementation would have summed.
	if sparseContribution >= sparseApparentSize/2 {
		t.Errorf(
			"a sparse deleted file's apparent size (%d bytes) leaked into the total (contributed %d bytes) — "+
				"deletedOpenBytes must use real allocated blocks (st.Blocks), not apparent size (st.Size), "+
				"or a memfd/sparse file falsely reports terabytes of \"disk space held\"",
			sparseApparentSize, sparseContribution,
		)
	}
}

func TestHasReadOnlyMount(t *testing.T) {
	cases := []struct {
		name   string
		mounts string
		want   bool
	}{
		{
			name: "all read-write",
			mounts: "/dev/sda1 / ext4 rw,relatime 0 0\n" +
				"/dev/sda2 /data xfs rw,noatime 0 0\n",
			want: false,
		},
		{
			name: "real fs remounted read-only (kernel I/O error)",
			mounts: "/dev/sda1 / ext4 ro,relatime 0 0\n" +
				"/dev/sda2 /data xfs rw,noatime 0 0\n",
			want: true,
		},
		{
			name:   "read-only-by-design fs is ignored",
			mounts: "/dev/loop0 /snap/core squashfs ro,nodev 0 0\n",
			want:   false,
		},
		{
			name:   "pseudo/ro system mounts are ignored",
			mounts: "sysfs /sys sysfs ro,nosuid 0 0\nproc /proc proc rw 0 0\n",
			want:   false,
		},
		{
			name:   "empty",
			mounts: "",
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasReadOnlyMount(tc.mounts); got != tc.want {
				t.Fatalf("hasReadOnlyMount = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsContainerRuntimeMount(t *testing.T) {
	cases := []struct {
		mount string
		want  bool
	}{
		{"/run/docker/runtime-runc/moby/8d9b02905780b33569f4e36d3bf52d5047f83ebca332b62d7c967d2dae4ff920/runc.OrA214", true},
		{"/var/lib/docker/overlay2/abc123/merged", true},
		{"/run/containerd/io.containerd.runtime.v2.task/default/x", true},
		{"/var/lib/containers/storage/overlay/x", true},
		{"/", false},
		{"/data", false},
		{"/run", false}, // the bare /run mount itself is real, not a runtime artifact
	}
	for _, tc := range cases {
		t.Run(tc.mount, func(t *testing.T) {
			if got := isContainerRuntimeMount(tc.mount); got != tc.want {
				t.Fatalf("isContainerRuntimeMount(%q) = %v, want %v", tc.mount, got, tc.want)
			}
		})
	}
}

func TestParseSmartctlJSON(t *testing.T) {
	t.Run("healthy NVMe with wear", func(t *testing.T) {
		j := `{"smart_status":{"passed":true},"nvme_smart_health_information_log":{"percentage_used":8}}`
		h, life, _ := parseSmartctlJSON([]byte(j))
		if h != "ok" {
			t.Fatalf("health = %q, want ok", h)
		}
		if life == nil || *life != 92 {
			t.Fatalf("life = %v, want 92", life)
		}
	})

	t.Run("failed drive", func(t *testing.T) {
		j := `{"smart_status":{"passed":false}}`
		h, _, _ := parseSmartctlJSON([]byte(j))
		if h != "fail" {
			t.Fatalf("health = %q, want fail", h)
		}
	})

	t.Run("worn NVMe flips to warning", func(t *testing.T) {
		j := `{"smart_status":{"passed":true},"nvme_smart_health_information_log":{"percentage_used":85}}`
		h, life, _ := parseSmartctlJSON([]byte(j))
		if h != "warning" {
			t.Fatalf("health = %q, want warning (life %v)", h, life)
		}
	})

	t.Run("garbage input", func(t *testing.T) {
		h, life, _ := parseSmartctlJSON([]byte("not json"))
		if h != "" || life != nil {
			t.Fatalf("want empty on garbage, got %q %v", h, life)
		}
	})

	t.Run("pending sectors flag warning via RAW even when normalized is 100", func(t *testing.T) {
		j := `{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[
			{"id":5,"name":"Reallocated_Sector_Ct","value":100,"raw":{"value":0}},
			{"id":197,"name":"Current_Pending_Sector","value":100,"raw":{"value":24}}]}}`
		h, _, _ := parseSmartctlJSON([]byte(j))
		if h != "warning" {
			t.Fatalf("health = %q, want warning", h)
		}
	})

	t.Run("ATA error log entries flag warning despite PASSED", func(t *testing.T) {
		j := `{"smart_status":{"passed":true},"ata_smart_error_log":{"summary":{"count":13}}}`
		h, _, _ := parseSmartctlJSON([]byte(j))
		if h != "warning" {
			t.Fatalf("health = %q, want warning", h)
		}
	})

	t.Run("NVMe media errors flag warning", func(t *testing.T) {
		j := `{"smart_status":{"passed":true},"nvme_smart_health_information_log":{"percentage_used":3,"media_errors":2}}`
		h, _, _ := parseSmartctlJSON([]byte(j))
		if h != "warning" {
			t.Fatalf("health = %q, want warning", h)
		}
	})

	t.Run("clean SATA attributes stay ok", func(t *testing.T) {
		j := `{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[
			{"id":5,"name":"Reallocated_Sector_Ct","value":100,"raw":{"value":0}},
			{"id":197,"name":"Current_Pending_Sector","value":100,"raw":{"value":0}}]},"ata_smart_error_log":{"summary":{"count":0}}}`
		h, _, _ := parseSmartctlJSON([]byte(j))
		if h != "ok" {
			t.Fatalf("health = %q, want ok", h)
		}
	})

	t.Run("reads drive temperature", func(t *testing.T) {
		j := `{"smart_status":{"passed":true},"temperature":{"current":47}}`
		_, _, temp := parseSmartctlJSON([]byte(j))
		if temp == nil || *temp != 47 {
			t.Fatalf("temp = %v, want 47", temp)
		}
	})
}
