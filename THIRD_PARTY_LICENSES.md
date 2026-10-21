# Third-party licenses

Go modules compiled into the Linux agent and the Kubernetes collector
(`go list -deps` for `GOOS=linux`, licenses detected with
`go-licenses report`). Every license here is permissive (MIT, ISC,
BSD-3-Clause, Apache-2.0) and compatible with distributing the agent under
Apache-2.0. The full license texts ship inside each module (see the Go
module cache or `go mod vendor`).

Regenerated 21 Oct 2026 from the agent source in this repository. Regenerate
whenever `go.mod` changes:

```sh
go install github.com/google/go-licenses@v1.6.0
GOOS=linux go-licenses report ./... ./cmd/k8s-agent
```

| Module | Version | License |
|---|---|---|
| `github.com/coder/websocket` | `v1.8.15` | ISC |
| `github.com/creack/pty` | `v1.1.24` | MIT |
| `github.com/davecgh/go-spew` | `v1.1.2-0.20180830191138-d8f796af33cc` | ISC |
| `github.com/dustin/go-humanize` | `v1.0.1` | MIT |
| `github.com/emicklei/go-restful/v3` | `v3.11.0` | MIT |
| `github.com/fxamacker/cbor/v2` | `v2.7.0` | MIT |
| `github.com/go-logr/logr` | `v1.4.2` | Apache-2.0 |
| `github.com/go-openapi/jsonpointer` | `v0.19.6` | Apache-2.0 |
| `github.com/go-openapi/jsonreference` | `v0.20.2` | Apache-2.0 |
| `github.com/go-openapi/swag` | `v0.22.4` | Apache-2.0 |
| `github.com/gogo/protobuf` | `v1.3.2` | BSD-3-Clause |
| `github.com/golang/protobuf` | `v1.5.4` | BSD-3-Clause |
| `github.com/google/gnostic-models` | `v0.6.8` | Apache-2.0 |
| `github.com/google/go-cmp` | `v0.6.0` | BSD-3-Clause |
| `github.com/google/gofuzz` | `v1.2.0` | Apache-2.0 |
| `github.com/google/uuid` | `v1.6.0` | BSD-3-Clause |
| `github.com/imdario/mergo` | `v0.3.6` | BSD-3-Clause |
| `github.com/josharian/intern` | `v1.0.0` | MIT |
| `github.com/json-iterator/go` | `v1.1.12` | MIT |
| `github.com/mailru/easyjson` | `v0.7.7` | MIT |
| `github.com/mattn/go-isatty` | `v0.0.16` | MIT |
| `github.com/modern-go/concurrent` | `v0.0.0-20180306012644-bacd9c7ef1dd` | Apache-2.0 |
| `github.com/modern-go/reflect2` | `v1.0.2` | Apache-2.0 |
| `github.com/munnerz/goautoneg` | `v0.0.0-20191010083416-a7dc8b61c822` | BSD-3-Clause |
| `github.com/ncruces/go-strftime` | `v0.1.9` | MIT |
| `github.com/remyoudompheng/bigfft` | `v0.0.0-20230129092748-24d4a6f8daec` | BSD-3-Clause |
| `github.com/shirou/gopsutil/v3` | `v3.24.1` | BSD-3-Clause |
| `github.com/spf13/pflag` | `v1.0.5` | BSD-3-Clause |
| `github.com/tklauser/go-sysconf` | `v0.3.12` | BSD-3-Clause |
| `github.com/tklauser/numcpus` | `v0.6.1` | Apache-2.0 |
| `github.com/x448/float16` | `v0.8.4` | MIT |
| `golang.org/x/net` | `v0.60.0` | BSD-3-Clause |
| `golang.org/x/oauth2` | `v0.27.0` | BSD-3-Clause |
| `golang.org/x/sys` | `v0.48.0` | BSD-3-Clause |
| `golang.org/x/term` | `v0.46.0` | BSD-3-Clause |
| `golang.org/x/text` | `v0.42.0` | BSD-3-Clause |
| `golang.org/x/time` | `v0.3.0` | BSD-3-Clause |
| `google.golang.org/protobuf` | `v1.34.2` | BSD-3-Clause |
| `gopkg.in/inf.v0` | `v0.9.1` | BSD-3-Clause |
| `gopkg.in/yaml.v2` | `v2.4.0` | Apache-2.0 |
| `gopkg.in/yaml.v3` | `v3.0.1` | MIT AND Apache-2.0 |
| `k8s.io/api` | `v0.31.14` | Apache-2.0 |
| `k8s.io/apimachinery` | `v0.31.14` | Apache-2.0 AND BSD-3-Clause |
| `k8s.io/client-go` | `v0.31.14` | Apache-2.0 |
| `k8s.io/klog/v2` | `v2.130.1` | Apache-2.0 |
| `k8s.io/kube-openapi` | `v0.0.0-20240228011516-70dd3763d340` | Apache-2.0 AND BSD-3-Clause |
| `k8s.io/metrics` | `v0.31.14` | Apache-2.0 |
| `k8s.io/utils` | `v0.0.0-20240711033017-18e509b52bc8` | Apache-2.0 AND BSD-3-Clause |
| `modernc.org/libc` | `v1.41.0` | MIT AND BSD-3-Clause |
| `modernc.org/mathutil` | `v1.6.0` | BSD-3-Clause |
| `modernc.org/memory` | `v1.7.2` | BSD-3-Clause |
| `modernc.org/sqlite` | `v1.29.0` | BSD-3-Clause |
| `sigs.k8s.io/json` | `v0.0.0-20221116044647-bc3834ca7abd` | Apache-2.0 |
| `sigs.k8s.io/structured-merge-diff/v4` | `v4.4.1` | Apache-2.0 |
| `sigs.k8s.io/yaml` | `v1.4.0` | MIT AND BSD-3-Clause AND Apache-2.0 |

Listed in `go.mod` but not linked into Linux builds: `go-ole`, `wmi`
(Windows, MIT), `go-m1cpu` (macOS, MPL-2.0), `plan9stats`, `perfstat`
(other OSes), and the modernc test helpers. They are pulled in transitively
by gopsutil and never compiled for `GOOS=linux`.
