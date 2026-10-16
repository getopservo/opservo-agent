package collectors

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseTunnelYAML(t *testing.T) {
	cfg := []byte(`tunnel: 4ae2340d-6a10-4170-93f9-c4a66a7c8bd9
credentials-file: /root/.cloudflared/4ae2340d.json
ingress:
  - hostname: redmine.example.com
    service: http://localhost:8080
  - hostname: api.example.com
    path: /v1
    service: http://127.0.0.1:3000
  - service: http_status:404
`)
	got := parseTunnelYAML(cfg)
	want := []tunnelRoute{
		{Hostname: "redmine.example.com", Service: "http://localhost:8080"},
		{Hostname: "api.example.com", Service: "http://127.0.0.1:3000"},
		{Service: "http_status:404"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestParseTunnelConfigJSON(t *testing.T) {
	nested := `{"version":3,"config":{"ingress":[{"hostname":"a.example.com","service":"http://localhost:8080","originRequest":{}},{"service":"http_status:404"}],"warp-routing":{"enabled":false}}}`
	if got := parseTunnelConfigJSON([]byte(nested)); len(got) != 2 || got[0].Hostname != "a.example.com" {
		t.Fatalf("nested: %+v", got)
	}
	asString := `{"version":3,"config":"{\"ingress\":[{\"hostname\":\"b.example.com\",\"service\":\"http://localhost:9000\"}]}"}`
	if got := parseTunnelConfigJSON([]byte(asString)); len(got) != 1 || got[0].Service != "http://localhost:9000" {
		t.Fatalf("string config: %+v", got)
	}
	if got := parseTunnelConfigJSON([]byte(`not json`)); got != nil {
		t.Fatalf("garbage: %+v", got)
	}
}

func TestParseTunnelLog_NewestWins(t *testing.T) {
	log := strings.Join([]string{
		`2026-10-01T10:00:00Z INF Updated to new configuration config="{\"ingress\":[{\"hostname\":\"old.example.com\",\"service\":\"http://localhost:1\"}]}" version=1`,
		`2026-10-01T10:00:01Z INF Registered tunnel connection connIndex=0`,
		`2026-10-02T10:00:00Z INF Updated to new configuration config="{\"ingress\":[{\"hostname\":\"redmine.example.com\", \"service\":\"http://localhost:8080\"}, {\"service\":\"http_status:404\"}], \"warp-routing\":{\"enabled\":false}}" version=2`,
	}, "\n")
	got := parseTunnelLog(log)
	if len(got) != 2 || got[0].Hostname != "redmine.example.com" || got[0].Service != "http://localhost:8080" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseDockerPorts(t *testing.T) {
	got := parseDockerPorts("0.0.0.0:8080->80/tcp, :::8080->80/tcp, 127.0.0.1:5433->5432/tcp, 6379/tcp, 0.0.0.0:6000-6001->6000-6001/udp")
	want := []PublishedPort{
		{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		{HostIP: "127.0.0.1", HostPort: 5433, ContainerPort: 5432, Protocol: "tcp"},
		{HostIP: "0.0.0.0", HostPort: 6000, ContainerPort: 6000, Protocol: "udp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestMergeDockerPS(t *testing.T) {
	stats := []ContainerStat{{Name: "redmine-deploy-proxy-1"}, {Name: "redmine-deploy-app-1"}}
	ps := "redmine-deploy-proxy-1\tnginx:1.27-alpine\tredmine-deploy\tUp 4 weeks\t0.0.0.0:8080->80/tcp, :::8080->80/tcp\n" +
		"redmine-deploy-app-1\tregistry.example.com/redmine:6\tredmine-deploy\tRestarting (1) 12 seconds ago\t\n" +
		"not-in-stats\tx\t\t\t\n"
	mergeDockerPS(stats, ps)
	if stats[0].Image != "nginx:1.27-alpine" || stats[0].Project != "redmine-deploy" || len(stats[0].Ports) != 1 || stats[0].Ports[0].HostPort != 8080 {
		t.Fatalf("proxy: %+v", stats[0])
	}
	if !strings.HasPrefix(stats[1].Status, "Restarting") || stats[1].Ports != nil {
		t.Fatalf("app: %+v", stats[1])
	}
}
