package collectors

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/disk"
)

// StorageCollector gathers the deeper storage-health facts the OpsServo Health
// Standard (OHS) storage rules consume: inode exhaustion, read-only remounts,
// and SMART / SSD-wear where smartctl is available. Basic disk-usage % stays in
// the system collector. Every probe is best-effort: a missing tool or permission
// leaves that field unset (→ the corresponding OHS rule stays dormant) rather
// than reporting a misleading value.
//
// JSON key: "storage" → snapshot.storage (read by the Opservo API).
type StorageCollector struct{}

func NewStorageCollector() *StorageCollector { return &StorageCollector{} }
func (c *StorageCollector) Name() string     { return "storage" }

// StorageReport is the collector output. Pointer / omitempty fields are omitted
// when unknown so the API treats them as "not collected" (dormant), not as a
// healthy zero.
type StorageReport struct {
	InodesPercent float64   `json:"inodes_percent"`             // worst inode-usage % across real mounts
	ReadOnly      bool      `json:"read_only"`                  // a real filesystem is mounted read-only
	Smart         string    `json:"smart,omitempty"`            // "ok" | "warning" | "fail" (omitted if unknown)
	SSDLifePct    *float64  `json:"ssd_life_percent,omitempty"` // estimated remaining SSD life %
	DriveTempC    *float64  `json:"drive_temp_c,omitempty"`     // hottest drive temperature (°C), via smartctl
	ArrayStatus   string    `json:"array_status,omitempty"`     // "" | "ok" | "degraded" — mdadm/zpool/LVM aggregate
	ArrayDetail   string    `json:"array_detail,omitempty"`     // what's degraded (e.g. "md0 degraded")
	MountFailed   bool      `json:"mount_failed"`               // a systemd .mount unit is in the failed state
	DeletedOpen   uint64    `json:"deleted_open_bytes"`         // space held by deleted-but-still-open files (df sees it, du can't)
	CollectedAt   time.Time `json:"collected_at"`
}

const storageCmdTimeout = 5 * time.Second

func (c *StorageCollector) Collect(ctx context.Context) (interface{}, error) {
	report := &StorageReport{CollectedAt: time.Now().UTC()}

	report.InodesPercent = worstInodePercent(ctx)
	report.ReadOnly = hasReadOnlyMount(readProcMounts())

	if hasBinary("smartctl") {
		health, life, temp := smartHealth(ctx)
		if health != "" {
			report.Smart = health
		}
		if life != nil {
			report.SSDLifePct = life
		}
		if temp != nil {
			report.DriveTempC = temp
		}
	}

	report.ArrayStatus, report.ArrayDetail = arrayHealth(ctx)
	report.MountFailed = anyMountUnitFailed(ctx)
	report.DeletedOpen = deletedOpenBytes()

	return report, nil
}

// deletedOpenBytes sums the actual disk space held by files that have been
// deleted but are still held open by a process — space `df` counts but `du`
// can't see (the classic "disk full but I can't find what's using it"). Scans
// /proc/<pid>/fd for magic links ending " (deleted)"; needs root to see other
// processes' fds. Deduped by (device, inode) so a file open by many processes
// counts once.
//
// Uses st.Blocks (real allocated 512-byte blocks), NOT st.Size (apparent
// size): a sparse deleted file — most commonly a memfd anonymous-memory
// mapping, e.g. the .NET/CoreCLR "doublemapper" GC technique the GitHub
// Actions Runner uses — can report a multi-TiB apparent size while occupying
// only a few MB of real memory/disk. Summing st.Size directly turned that
// into a false "2048 GiB held by deleted files" finding. For a genuinely
// space-holding deleted file (e.g. a rotated log still being written),
// st.Blocks*512 tracks st.Size closely, so this doesn't change real cases.
func deletedOpenBytes() uint64 {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	var total uint64
	seen := map[[2]uint64]bool{}
	for _, pe := range procs {
		name := pe.Name()
		if name[0] < '0' || name[0] > '9' {
			continue
		}
		fdDir := "/proc/" + name + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fe := range fds {
			p := fdDir + "/" + fe.Name()
			link, err := os.Readlink(p)
			if err != nil || !strings.HasSuffix(link, " (deleted)") {
				continue
			}
			var st syscall.Stat_t
			if err := syscall.Stat(p, &st); err != nil {
				continue
			}
			if st.Size <= 0 || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
				continue
			}
			actual := uint64(st.Blocks) * 512
			if actual == 0 {
				continue
			}
			key := [2]uint64{uint64(st.Dev), st.Ino}
			if seen[key] {
				continue
			}
			seen[key] = true
			total += actual
		}
	}
	return total
}

// arrayHealth aggregates software-RAID (mdadm), ZFS (zpool) and LVM health into
// a single ("ok"|"degraded"|"") verdict + a short detail string. "" means no
// array subsystem is present (→ the check stays dormant/neutral).
func arrayHealth(ctx context.Context) (string, string) {
	detail := ""
	found := false // an actual array/pool/volume exists on this host
	deg := false
	degraded := func(what string) {
		deg = true
		if detail != "" {
			detail += "; "
		}
		detail += what
	}

	// mdadm: /proc/mdstat — an "mdN" device line means an array exists; a "_" in
	// the [UU] member block means a missing/failed member.
	if data, err := os.ReadFile("/proc/mdstat"); err == nil {
		md := ""
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "md") {
				md = strings.Fields(line)[0]
				found = true
			}
			if i := strings.LastIndex(line, "["); i >= 0 && strings.Contains(line[i:], "_") && md != "" {
				degraded(md + " degraded")
				md = ""
			}
		}
	}

	// ZFS: `zpool status -x` prints "all pools are healthy" when a pool exists and
	// is fine; "no pools available" when ZFS is present but has no pools.
	if hasBinary("zpool") {
		if out, err := runCmdTimeout(ctx, storageCmdTimeout, "zpool", "status", "-x"); err == nil {
			s := strings.ToLower(strings.TrimSpace(string(out)))
			if s != "" && !strings.Contains(s, "no pools available") {
				found = true
				if !strings.Contains(s, "all pools are healthy") {
					degraded("zpool unhealthy")
				}
			}
		}
	}

	// LVM: a "p" (partial) attribute in `lvs -o lv_attr` flags a missing PV.
	if hasBinary("lvs") {
		if out, err := runCmdTimeout(ctx, storageCmdTimeout, "lvs", "--noheadings", "-o", "lv_attr"); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				attr := strings.TrimSpace(line)
				if attr == "" {
					continue
				}
				found = true
				if len(attr) > 8 && strings.Contains(attr, "p") {
					degraded("LVM volume partial")
					break
				}
			}
		}
	}

	if deg {
		return "degraded", detail
	}
	if found {
		return "ok", ""
	}
	return "", "" // no array subsystem → check stays n/a
}

// anyMountUnitFailed reports whether systemd has a .mount unit in the failed
// state (an fstab/automount entry that could not mount).
func anyMountUnitFailed(ctx context.Context) bool {
	if !hasBinary("systemctl") {
		return false
	}
	out, err := runCmdTimeout(ctx, storageCmdTimeout, "systemctl", "--failed", "--type=mount", "--no-legend", "--plain")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// worstInodePercent returns the highest inode-usage % across real filesystems,
// or 0 if none can be read (0 is a safe "healthy" default; inodes are always
// readable via statfs, unlike SMART).
func worstInodePercent(ctx context.Context) float64 {
	worst := 0.0
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return 0
	}
	for _, p := range parts {
		if pseudoFS[p.Fstype] || strings.HasPrefix(p.Mountpoint, "/sys") || strings.HasPrefix(p.Mountpoint, "/proc") || strings.HasPrefix(p.Mountpoint, "/dev") {
			continue
		}
		// Docker/containerd overlay mounts (one per running container) aren't
		// real storage — they're the same underlying host filesystem, and
		// overlayfs's statfs() inode counts are notoriously unreliable (many
		// kernels report 0 free / 100% used for the merged view regardless of
		// actual disk state). Without this, a host running several containers
		// permanently pins at "100% inodes used" no matter how empty the real
		// disk is — unfixable by any remediation since the number is simply
		// wrong, not stale. isContainerRuntimeMount catches the /var/lib/docker
		// bind-mount paths too, for the same reason.
		if readOnlyByDesign[p.Fstype] || isContainerRuntimeMount(p.Mountpoint) {
			continue
		}
		u, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil || u == nil {
			continue
		}
		if u.InodesUsedPercent > worst {
			worst = u.InodesUsedPercent
		}
	}
	return worst
}

func readProcMounts() string {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}
	return string(data)
}

// Pseudo/virtual filesystems that aren't real storage.
var pseudoFS = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "sysfs": true, "proc": true, "cgroup": true,
	"cgroup2": true, "devpts": true, "mqueue": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "pstore": true, "bpf": true, "configfs": true, "fusectl": true,
	"binfmt_misc": true, "autofs": true, "hugetlbfs": true, "ramfs": true,
}

// isContainerRuntimeMount reports whether a mount point is a container-runtime
// implementation detail (runc/containerd bind-mounts and overlay diff/merged
// dirs, docker's internal storage) rather than storage an operator manages.
// These come and go with container lifecycles and their "disk" is really the
// host filesystem underneath — alerting on them by path is both noisy and
// useless (the path includes a container ID and is gone once it exits).
func isContainerRuntimeMount(mount string) bool {
	for _, prefix := range []string{"/run/docker", "/run/containerd", "/var/lib/docker", "/var/lib/containers", "/run/runc"} {
		if strings.HasPrefix(mount, prefix) {
			return true
		}
	}
	return false
}

// Filesystems that are read-only by design — excluded from the read-only alarm.
var readOnlyByDesign = map[string]bool{
	"squashfs": true, "iso9660": true, "overlay": true, "erofs": true,
}

// hasReadOnlyMount reports whether any REAL filesystem is mounted read-only,
// parsing /proc/mounts lines: "<dev> <mountpoint> <fstype> <opts> ...". A real
// filesystem going read-only almost always means the kernel hit an I/O error.
func hasReadOnlyMount(procMounts string) bool {
	for _, line := range strings.Split(procMounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mount, fstype, opts := fields[1], fields[2], fields[3]
		if pseudoFS[fstype] || readOnlyByDesign[fstype] {
			continue
		}
		if strings.HasPrefix(mount, "/sys") || strings.HasPrefix(mount, "/proc") || strings.HasPrefix(mount, "/dev") || strings.HasPrefix(mount, "/run") {
			continue
		}
		for _, o := range strings.Split(opts, ",") {
			if o == "ro" {
				return true
			}
		}
	}
	return false
}

// smartHealth runs smartctl across block devices and returns the aggregate
// health ("ok"/"warning"/"fail", worst wins) and the lowest remaining-life %.
// Requires smartctl + root; on any failure it yields "" / nil (→ dormant).
func smartHealth(ctx context.Context) (string, *float64, *float64) {
	devs := blockDevices()
	if len(devs) == 0 {
		return "", nil, nil
	}
	worst := "" // "" < ok < warning < fail
	rank := map[string]int{"": 0, "ok": 1, "warning": 2, "fail": 3}
	var life *float64
	var temp *float64 // hottest drive wins
	for _, dev := range devs {
		out, err := runCmdTimeout(ctx, storageCmdTimeout, "smartctl", "-H", "-A", "-j", dev)
		if err != nil && len(out) == 0 {
			continue
		}
		h, l, t := parseSmartctlJSON(out)
		if rank[h] > rank[worst] {
			worst = h
		}
		if l != nil && (life == nil || *l < *life) {
			life = l
		}
		if t != nil && (temp == nil || *t > *temp) {
			temp = t
		}
	}
	return worst, life, temp
}

// blockDevices lists candidate whole-disk devices to probe with SMART.
func blockDevices() []string {
	var out []string
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		// Whole disks only: sd*, nvme*n*, vd*, hd*. Skip loop/ram/dm/zram/sr.
		if strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "hd") ||
			(strings.HasPrefix(name, "nvme") && strings.Contains(name, "n")) {
			out = append(out, "/dev/"+name)
		}
	}
	return out
}

// parseSmartctlJSON extracts the overall-health verdict and remaining-life %
// from `smartctl -H -A -j` output. Returns ("ok"|"warning"|"fail", life%|nil).
func parseSmartctlJSON(data []byte) (string, *float64, *float64) {
	var s struct {
		SmartStatus struct {
			Passed bool `json:"passed"`
		} `json:"smart_status"`
		// NVMe wear indicator.
		NVMeHealth struct {
			PercentageUsed *int   `json:"percentage_used"`
			MediaErrors    *int64 `json:"media_errors"` // data-integrity failures — hardware-level, not reflected in "passed"
		} `json:"nvme_smart_health_information_log"`
		// SATA/ATA attributes table.
		ATA struct {
			Table []struct {
				Name  string `json:"name"`
				Value int    `json:"value"` // vendor-normalized (100 = healthy); only moves once the drive is badly degraded
				Raw   struct {
					Value int64 `json:"value"` // the actual count (sectors, errors)
				} `json:"raw"`
			} `json:"table"`
		} `json:"ata_smart_attributes"`
		// Drive-side ATA error log: any logged command error is a hardware-level
		// failure the overall self-assessment ("PASSED") does not reflect.
		ATAErrorLog struct {
			Summary struct {
				Count int `json:"count"`
			} `json:"summary"`
		} `json:"ata_smart_error_log"`
		Temperature struct {
			Current *int `json:"current"`
		} `json:"temperature"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return "", nil, nil
	}

	health := "ok"
	if !s.SmartStatus.Passed {
		health = "fail"
	}

	var temp *float64
	if s.Temperature.Current != nil {
		t := float64(*s.Temperature.Current)
		temp = &t
	}

	var life *float64
	// NVMe: percentage_used is 0..100+ used → remaining = 100 - used.
	if s.NVMeHealth.PercentageUsed != nil {
		rem := 100.0 - float64(*s.NVMeHealth.PercentageUsed)
		if rem < 0 {
			rem = 0
		}
		life = &rem
	}
	// SATA: read wear/health attributes; low normalized values flag warnings.
	for _, a := range s.ATA.Table {
		n := strings.ToLower(a.Name)
		if strings.Contains(n, "wear_leveling") || strings.Contains(n, "ssd_life") || n == "percent_lifetime_remain" || strings.Contains(n, "media_wearout") {
			v := float64(a.Value) // normalized value ~ remaining life %
			if life == nil {
				life = &v
			}
		}
		if strings.Contains(n, "reallocated_sector") || strings.Contains(n, "reallocated_event") || strings.Contains(n, "pending_sector") || strings.Contains(n, "uncorrectable") || strings.Contains(n, "udma_crc_error") || strings.Contains(n, "reported_uncorrect") {
			// The RAW value is the real count. The normalized value stays at 100
			// until the drive is badly degraded, which is why a disk throwing
			// UNC/IDNF errors used to be reported "ok" here.
			if (a.Raw.Value > 0 || (a.Value > 0 && a.Value < 100)) && health == "ok" {
				health = "warning"
			}
		}
	}
	if s.ATAErrorLog.Summary.Count > 0 && health == "ok" {
		health = "warning"
	}
	if s.NVMeHealth.MediaErrors != nil && *s.NVMeHealth.MediaErrors > 0 && health == "ok" {
		health = "warning"
	}
	if life != nil && *life < 20 && health == "ok" {
		health = "warning"
	}
	return health, life, temp
}
