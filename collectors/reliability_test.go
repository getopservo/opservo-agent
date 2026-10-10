package collectors

import (
	"testing"
	"time"
)

func TestParseKernelSignals(t *testing.T) {
	t.Run("clean log", func(t *testing.T) {
		r := parseKernelSignals("Linux version 6.1\nusb 1-1: new device\n")
		if r.OOMKills != 0 || r.KernelPanic || r.Segfaults != 0 || r.FilesystemErrors || r.RemountRO {
			t.Fatalf("expected all-clear, got %+v", r)
		}
	})

	t.Run("oom kills counted, preamble ignored", func(t *testing.T) {
		log := "node invoked oom-killer: gfp_mask=0x100\n" +
			"Out of memory: Killed process 1234 (node) total-vm:...\n" +
			"Out of memory: Killed process 5678 (php) total-vm:...\n"
		r := parseKernelSignals(log)
		if r.OOMKills != 2 {
			t.Fatalf("OOMKills = %d, want 2", r.OOMKills)
		}
	})

	t.Run("kernel panic", func(t *testing.T) {
		r := parseKernelSignals("Kernel panic - not syncing: VFS: Unable to mount root fs\n")
		if !r.KernelPanic {
			t.Fatal("expected KernelPanic true")
		}
	})

	t.Run("segfaults", func(t *testing.T) {
		r := parseKernelSignals("myapp[2211]: segfault at 0 ip 00007f rip ... error 4\n")
		if r.Segfaults != 1 {
			t.Fatalf("Segfaults = %d, want 1", r.Segfaults)
		}
	})

	t.Run("filesystem error + read-only remount", func(t *testing.T) {
		log := "EXT4-fs error (device sda1): ext4_find_entry:1234: inode #2\n" +
			"EXT4-fs (sda1): Remounting filesystem read-only\n"
		r := parseKernelSignals(log)
		if !r.FilesystemErrors {
			t.Fatal("expected FilesystemErrors true")
		}
		if !r.RemountRO {
			t.Fatal("expected RemountRO true")
		}
	})

	t.Run("hardware (MCE) + hung tasks", func(t *testing.T) {
		log := "mce: [Hardware Error]: Machine check events logged\n" +
			"INFO: task jbd2/sda1-8:200 blocked for more than 120 seconds.\n"
		r := parseKernelSignals(log)
		if r.MCEErrors != 1 {
			t.Fatalf("MCEErrors = %d, want 1", r.MCEErrors)
		}
		if r.HungTasks != 1 {
			t.Fatalf("HungTasks = %d, want 1", r.HungTasks)
		}
	})
}

func TestRebootsWithin(t *testing.T) {
	now := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	listBoots := "" +
		" -3 abc Sat 2026-07-01 09:00:00 UTC—Sat 2026-07-01 18:00:00 UTC\n" + // outside 24h
		" -2 def Mon 2026-07-07 02:00:00 UTC—Mon 2026-07-07 05:00:00 UTC\n" + // within 24h
		" -1 ghi Mon 2026-07-07 06:00:00 UTC—Mon 2026-07-07 09:00:00 UTC\n" + // within 24h
		"  0 jkl Mon 2026-07-07 09:30:00 UTC—Mon 2026-07-07 12:00:00 UTC\n" // within 24h (current)
	// 3 boots started within 24h → 2 reboots.
	if got := rebootsWithin(listBoots, now, 24*time.Hour); got != 2 {
		t.Fatalf("rebootsWithin = %d, want 2", got)
	}
	// A single boot in the window is not a reboot.
	single := "  0 jkl Mon 2026-07-07 09:30:00 UTC—Mon 2026-07-07 12:00:00 UTC\n"
	if got := rebootsWithin(single, now, 24*time.Hour); got != 0 {
		t.Fatalf("rebootsWithin(single) = %d, want 0", got)
	}
}

// TestRebootsWithin_NonUTCNow is a regression test: a
// server whose local wall clock isn't UTC (e.g. IST, UTC+5:30) must still get
// the same answer as an equivalent UTC `now`, since journalctl output is
// always UTC (the caller passes --utc) but `now` itself used to be built from
// local time before the fix. `now` here is the SAME INSTANT as the UTC test
// above, just expressed in a non-UTC location, proving the comparison is
// timezone-invariant (time.Time compares absolute instants, not wall clock).
func TestRebootsWithin_NonUTCNow(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+30*60) // UTC+5:30, no DST — deterministic without a tzdata dependency
	nowUTC := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	nowIST := nowUTC.In(ist) // same instant, non-UTC location
	if nowIST.Location() == time.UTC {
		t.Fatal("test setup bug: nowIST must not be UTC")
	}
	listBoots := "" +
		" -3 abc Sat 2026-07-01 09:00:00 UTC—Sat 2026-07-01 18:00:00 UTC\n" + // outside 24h
		" -2 def Mon 2026-07-07 02:00:00 UTC—Mon 2026-07-07 05:00:00 UTC\n" + // within 24h
		" -1 ghi Mon 2026-07-07 06:00:00 UTC—Mon 2026-07-07 09:00:00 UTC\n" + // within 24h
		"  0 jkl Mon 2026-07-07 09:30:00 UTC—Mon 2026-07-07 12:00:00 UTC\n" // within 24h (current)
	gotUTC := rebootsWithin(listBoots, nowUTC, 24*time.Hour)
	gotIST := rebootsWithin(listBoots, nowIST, 24*time.Hour)
	if gotIST != 2 {
		t.Fatalf("rebootsWithin with non-UTC now = %d, want 2 (same as UTC now)", gotIST)
	}
	if gotIST != gotUTC {
		t.Fatalf("non-UTC now (%d) disagrees with UTC now (%d) for the same instant — timezone-dependent bug reintroduced", gotIST, gotUTC)
	}
}

func TestCountNonEmptyLines(t *testing.T) {
	if n := countNonEmptyLines("a\n\nb\n  \nc\n"); n != 3 {
		t.Fatalf("countNonEmptyLines = %d, want 3", n)
	}
}

func TestDiskErrorsFrom(t *testing.T) {
	t.Run("single failing SATA disk folds ata port into the block device", func(t *testing.T) {
		log := "ata1.00: exception Emask 0x10 SAct 0x0 SErr 0x4050000 action 0xe frozen\n" +
			"ata1.00: failed command: WRITE FPDMA QUEUED\n" +
			"ata1.00: status: { DRDY ERR }\n" +
			"ata1.00: error: { UNC }\n" +
			"I/O error, dev sda, sector 123456 op 0x0:(READ) flags 0x80700 phys_seg 1 prio class 2\n" +
			"Buffer I/O error on dev sda1, logical block 4711, lost async page write\n" +
			"sd 0:0:0:0: [sda] tag#12 access beyond end of device\n" +
			"EXT4-fs (sda1): failed to convert unwritten extents to written extents -- potential data loss! (inode 99, error -5)\n" +
			"EXT4-fs (sda1): Remounting filesystem read-only\n"
		r := parseKernelSignals(log)
		if len(r.DiskErrors) != 1 {
			t.Fatalf("DiskErrors = %+v, want exactly one device", r.DiskErrors)
		}
		d := r.DiskErrors[0]
		if d.Device != "sda" {
			t.Fatalf("Device = %q, want sda", d.Device)
		}
		if d.IOErrors != 4 {
			t.Fatalf("IOErrors = %d, want 4", d.IOErrors)
		}
		if d.ATAErrors != 4 {
			t.Fatalf("ATAErrors = %d, want 4", d.ATAErrors)
		}
		if d.Sample == "" || len(d.Sample) > 160 {
			t.Fatalf("bad sample %q", d.Sample)
		}
		if !r.FilesystemErrors || !r.RemountRO {
			t.Fatalf("expected FilesystemErrors+RemountRO, got %+v", r)
		}
	})

	t.Run("two block devices keep the ata port separate", func(t *testing.T) {
		log := "I/O error, dev sda, sector 1 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0\n" +
			"I/O error, dev nvme0n1, sector 2 op 0x1:(WRITE) flags 0x0 phys_seg 1 prio class 0\n" +
			"ata3.00: failed command: READ FPDMA QUEUED\n"
		r := parseKernelSignals(log)
		if len(r.DiskErrors) != 3 {
			t.Fatalf("DiskErrors = %+v, want sda, nvme0n1, ata3", r.DiskErrors)
		}
		if r.DiskErrors[2].Device != "ata3" || r.DiskErrors[2].ATAErrors != 1 {
			t.Fatalf("ata entry = %+v", r.DiskErrors[2])
		}
	})

	t.Run("nvme partition aggregates onto the namespace", func(t *testing.T) {
		log := "Buffer I/O error on dev nvme0n1p2, logical block 8, async page read\n" +
			"nvme nvme0: I/O cmd 0x2 timeout, aborting\n"
		r := parseKernelSignals(log)
		if len(r.DiskErrors) != 2 || r.DiskErrors[0].Device != "nvme0n1" || r.DiskErrors[1].Device != "nvme0" {
			t.Fatalf("DiskErrors = %+v", r.DiskErrors)
		}
	})

	t.Run("clean log has no disk errors", func(t *testing.T) {
		r := parseKernelSignals("usb 1-1: new high-speed USB device\nsd 0:0:0:0: [sda] Attached SCSI disk\n")
		if r.DiskErrors != nil {
			t.Fatalf("DiskErrors = %+v, want nil", r.DiskErrors)
		}
	})
}
