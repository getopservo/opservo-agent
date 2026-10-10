package collectors

import (
	"strings"
	"testing"
)

func TestSanitizeIdentity(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"  i-0abc123\n", "i-0abc123"},
		{"", ""},
		{"None", ""},
		{"none\n", ""},
		{"Unknown", ""},
		{"Default string", ""},
		{"Not Specified", ""},
		{"To Be Filled By O.E.M.", ""},
		{"4c4c4544-004d-3510-8054-b4c04f595931", "4c4c4544-004d-3510-8054-b4c04f595931"},
	}
	for _, c := range cases {
		if got := sanitizeIdentity(c.in); got != c.want {
			t.Errorf("sanitizeIdentity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPublicIPv4(t *testing.T) {
	cases := map[string]string{
		"203.0.113.71":    "203.0.113.71",
		" 203.0.113.71\n": "203.0.113.71",
		"10.20.0.49":      "",
		"192.168.1.50":    "",
		"172.16.5.5":      "",
		"100.64.1.1":      "",
		"169.254.169.254": "",
		"127.0.0.1":       "",
		"2600::1":         "",
		"not-an-ip":       "",
		"":                "",
	}
	for in, want := range cases {
		if got := publicIPv4(in); got != want {
			t.Errorf("publicIPv4(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPublicIPFromMetadata(t *testing.T) {
	imds := func(path string, _ int64) string {
		if path == "/latest/meta-data/public-ipv4" {
			return "3.3.3.3\n"
		}
		return ""
	}
	none := func(string, int64) string { return "" }
	gce := func() string { return "34.1.2.3" }
	if got := publicIPFromMetadata(imds, gce); got != "3.3.3.3" {
		t.Fatalf("EC2 should win: got %q", got)
	}
	if got := publicIPFromMetadata(none, gce); got != "34.1.2.3" {
		t.Fatalf("GCE fallback: got %q", got)
	}
	if got := publicIPFromMetadata(none, func() string { return "" }); got != "" {
		t.Fatalf("no metadata should yield empty, got %q", got)
	}
	// A private answer (e.g. IMDS behind a NAT-only subnet) is discarded.
	if got := publicIPFromMetadata(func(string, int64) string { return "10.0.0.1" }, func() string { return "" }); got != "" {
		t.Fatalf("private metadata answer must be discarded, got %q", got)
	}
}

func TestCloudResourceIDFrom(t *testing.T) {
	none := func() string { return "" }
	gceNone := func(string) string { return "" }
	gce := func(p string) string {
		switch p {
		case "project/project-id":
			return "my-proj"
		case "instance/zone":
			return "projects/123456/zones/asia-south1-a"
		case "instance/name":
			return "web-1"
		}
		return ""
	}
	if got := cloudResourceIDFrom(func() string { return "i-0abc" }, func() string { return "/subscriptions/x" }, gce); got != "i-0abc" {
		t.Fatalf("EC2 must win: %q", got)
	}
	arm := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
	if got := cloudResourceIDFrom(none, func() string { return arm }, gce); !strings.HasPrefix(got, "/subscriptions/") {
		t.Fatalf("Azure ARM id expected: %q", got)
	}
	if got := cloudResourceIDFrom(none, func() string { return "<html>not azure" }, gceNone); got != "" {
		t.Fatalf("garbage Azure answer must be ignored: %q", got)
	}
	want := "//compute.googleapis.com/projects/my-proj/zones/asia-south1-a/instances/web-1"
	if got := cloudResourceIDFrom(none, none, gce); got != want {
		t.Fatalf("GCE global_name: got %q want %q", got, want)
	}
	if got := cloudResourceIDFrom(none, none, gceNone); got != "" {
		t.Fatalf("bare metal must be empty: %q", got)
	}
	if gceGlobalName("p", "projects/1/zones/", "n") != "" {
		t.Fatal("empty zone must yield empty")
	}
}
