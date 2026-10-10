package collectors

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// InstanceIdentity returns the strongest available per-instance identity:
// EC2 IMDSv2 instance-id → DMI board_asset_tag (Nitro exposes "i-…" there
// even when IMDS is locked down) → MachineID(). A cloud instance id beats
// /etc/machine-id because baking an AMI preserves machine-id — every Auto
// Scaling clone would share it, defeating clone detection entirely.
//
// The install script computes the same value in the same order and records it
// as OPSERVO_MACHINE_ID, so a mismatch at startup means "this box is not the
// one the credentials were issued to" (an AMI clone), not an identity-source
// flake. Keep the two implementations in sync.
func InstanceIdentity() string {
	if id := ec2InstanceID(); id != "" {
		return id
	}
	if tag := dmiAssetTag(); strings.HasPrefix(tag, "i-") {
		return tag
	}
	return MachineID()
}

// ec2InstanceID fetches the instance id over IMDSv2. Short timeouts: on real
// EC2 the metadata service answers in microseconds; anywhere else the
// link-local address is unroutable and we must not stall agent startup.
func ec2InstanceID() string {
	return sanitizeIdentity(imdsGet("/latest/meta-data/instance-id", 256))
}

// imdsGet reads one IMDSv2 metadata path. Returns "" off-EC2, on any error,
// or when the path is absent (e.g. public-ipv4 on an instance without one).
func imdsGet(path string, max int64) string {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodPut, "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	token, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
	if len(token) == 0 {
		return ""
	}

	req, err = http.NewRequest(http.MethodGet, "http://169.254.169.254"+path, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-aws-ec2-metadata-token", strings.TrimSpace(string(token)))
	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, max))
	resp.Body.Close()
	return string(body)
}

// gceExternalIP reads the first external IP from the GCE metadata server.
func gceExternalIP() string {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	resp.Body.Close()
	return string(body)
}

var (
	publicIPMu      sync.Mutex
	publicIPCached  string
	publicIPChecked time.Time
	publicIPNextTTL time.Duration
)

// CloudPublicIP returns the instance's public IPv4 as reported by the cloud
// metadata service (EC2 IMDSv2, then GCE). The heartbeat's source address is
// NOT a substitute: behind a NAT gateway it is the gateway's IP, which nobody
// can SSH to. Cached — a hit is re-read every 10 min (Elastic IPs can be
// re-associated), a miss (bare metal, other clouds) only hourly so we don't
// pay two metadata timeouts on every collection.
func CloudPublicIP() string {
	publicIPMu.Lock()
	defer publicIPMu.Unlock()
	if !publicIPChecked.IsZero() && time.Since(publicIPChecked) < publicIPNextTTL {
		return publicIPCached
	}
	ip := publicIPFromMetadata(imdsGet, gceExternalIP)
	publicIPCached = ip
	publicIPChecked = time.Now()
	if ip != "" {
		publicIPNextTTL = 10 * time.Minute
	} else {
		publicIPNextTTL = time.Hour
	}
	return ip
}

// publicIPFromMetadata tries each metadata source in order and keeps the first
// value that is a real, globally routable IP. Split out so tests can inject
// fake fetchers.
func publicIPFromMetadata(imds func(path string, max int64) string, gce func() string) string {
	for _, raw := range []string{imds("/latest/meta-data/public-ipv4", 64), gce()} {
		if ip := publicIPv4(raw); ip != "" {
			return ip
		}
	}
	return ""
}

// publicIPv4 parses s and returns it only if it is a public (globally
// routable) IPv4 address; "" otherwise.
func publicIPv4(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil {
		return ""
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return ""
	}
	// Carrier-grade NAT (100.64.0.0/10) is not reachable from the internet either.
	if ip4 := ip.To4(); ip4[0] == 100 && ip4[1]&0xc0 == 64 {
		return ""
	}
	return ip.String()
}

func dmiAssetTag() string {
	data, err := os.ReadFile("/sys/class/dmi/id/board_asset_tag")
	if err != nil {
		return ""
	}
	return sanitizeIdentity(string(data))
}

// sanitizeIdentity trims whitespace and rejects values that can't be a real
// identity (empty, or DMI placeholder strings on non-cloud hardware).
func sanitizeIdentity(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "none", "unknown", "default string", "not specified", "to be filled by o.e.m.":
		return ""
	}
	return s
}

// ── Cloud resource id (cloud cost attribution) ─────────────────────────────
// The identifier the cloud's BILLING data uses for this box, so the API can
// join a server to its line items:
//   EC2   → instance id                   ("i-0abc…")
//   Azure → ARM resource id               ("/subscriptions/…/virtualMachines/vm1")
//   GCE   → billing export global_name    ("//compute.googleapis.com/projects/p/zones/z/instances/vm1")
// Deliberately separate from InstanceIdentity(): that value is pinned by the
// installer for AMI-clone detection and must not change meaning.

func azureResourceID() string {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/metadata/instance/compute/resourceId?api-version=2021-02-01&format=text", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata", "true")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
	return strings.TrimSpace(string(body))
}

func gceMeta(path string) string {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/"+path, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	resp.Body.Close()
	return strings.TrimSpace(string(body))
}

// gceGlobalName builds the billing-export resource.global_name from the three
// metadata values (project id, "projects/<num>/zones/<zone>", instance name).
func gceGlobalName(projectID, zonePath, name string) string {
	if projectID == "" || zonePath == "" || name == "" {
		return ""
	}
	zone := zonePath[strings.LastIndex(zonePath, "/")+1:]
	if zone == "" {
		return ""
	}
	return "//compute.googleapis.com/projects/" + projectID + "/zones/" + zone + "/instances/" + name
}

// cloudResourceIDFrom tries the providers in order; split out for tests.
func cloudResourceIDFrom(ec2 func() string, azure func() string, gce func(string) string) string {
	if id := ec2(); id != "" {
		return id
	}
	if id := azure(); strings.HasPrefix(id, "/subscriptions/") {
		return id
	}
	if g := gceGlobalName(gce("project/project-id"), gce("instance/zone"), gce("instance/name")); g != "" {
		return g
	}
	return ""
}

var (
	resIDMu      sync.Mutex
	resIDCached  string
	resIDChecked time.Time
)

// CloudResourceID returns the billing-side resource id for this box (see
// above), cached for an hour like CloudPublicIP: it never changes for a running
// instance, and three metadata timeouts per collection on bare metal would be
// wasteful.
func CloudResourceID() string {
	resIDMu.Lock()
	defer resIDMu.Unlock()
	if !resIDChecked.IsZero() && time.Since(resIDChecked) < time.Hour {
		return resIDCached
	}
	resIDCached = cloudResourceIDFrom(ec2InstanceID, azureResourceID, gceMeta)
	resIDChecked = time.Now()
	return resIDCached
}
