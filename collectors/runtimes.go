package collectors

import (
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"time"
)

// RuntimeInfo is one installed language runtime/toolchain and its version.
type RuntimeInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path,omitempty"`
}

// RuntimeCollector reports which language runtimes are installed (Node, Python,
// PHP, …) and their versions — useful for "what's installed here" and for
// flagging end-of-life versions.
type RuntimeCollector struct{}

func NewRuntimeCollector() *RuntimeCollector { return &RuntimeCollector{} }
func (r *RuntimeCollector) Name() string     { return "runtimes" }

var runtimeProbes = []struct {
	bin  string
	args []string
	name string
}{
	{"node", []string{"--version"}, "Node.js"},
	{"python3", []string{"--version"}, "Python"},
	{"php", []string{"--version"}, "PHP"},
	{"go", []string{"version"}, "Go"},
	{"ruby", []string{"--version"}, "Ruby"},
	{"java", []string{"-version"}, "Java"},
	{"deno", []string{"--version"}, "Deno"},
	{"bun", []string{"--version"}, "Bun"},
	{"dotnet", []string{"--version"}, ".NET"},
	{"perl", []string{"-v"}, "Perl"},
	{"rustc", []string{"--version"}, "Rust"},
}

var versionRe = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)

func (r *RuntimeCollector) Collect(ctx context.Context) (interface{}, error) {
	out := []RuntimeInfo{}
	for _, p := range runtimeProbes {
		path, err := exec.LookPath(p.bin)
		if err != nil {
			continue // not installed
		}
		cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		cmd := exec.CommandContext(cctx, p.bin, p.args...)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf // some runtimes (java, perl) print to stderr
		_ = cmd.Run()
		cancel()
		out = append(out, RuntimeInfo{
			Name:    p.name,
			Version: versionRe.FindString(buf.String()),
			Path:    path,
		})
	}
	return out, nil
}
