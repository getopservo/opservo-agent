# Opservo agent

The agent that runs on servers monitored by [Opservo](https://getopservo.com).
It collects facts about a Linux host (or a Kubernetes cluster), signs them, and
sends them to the Opservo API over HTTPS. The Opservo service turns those facts
into plain-English health findings and fixes.

This repository is the agent only. The API and dashboard are a hosted service
and are not part of this repository.

- Single static Go binary, no runtime dependencies, no CGO.
- Linux `amd64` and `arm64`.
- Licensed under Apache 2.0.

## What it collects

Every 60 seconds (configurable with `--interval`) the agent sends one heartbeat
containing:

| Area | What |
|------|------|
| System | OS, kernel, CPU, memory, disk, uptime, load, cloud instance identity and public IP (from the cloud metadata service, when present) |
| Processes | Running processes with CPU and memory per PID |
| Services | systemd units, Docker containers, PM2 processes |
| Network | Listening ports and which process owns them, basic network health |
| Apps | Detected frameworks (Laravel, WordPress, Node.js, Django, FastAPI, PHP) |
| Domains | nginx / Apache virtual hosts and TLS certificate expiry |
| Logs | New log lines from nginx, Apache, Laravel, Docker, PM2 and journald warnings (at most 200 per source per heartbeat, deduplicated between heartbeats) |
| Security | Exposed database ports, failed SSH logins, root login and SSH hardening settings, firewall state, suspicious processes, recent logins. Usernames and source IPs are masked on the host before sending (e.g. `alice` → `al***`, `1.2.3.4` → `1.2.*.*`). |
| Storage / reliability | Inode use, read-only remounts, SMART health, kernel I/O errors per disk, OOM kills, reboots |
| Maintenance | Pending package updates, reboot-required, runtimes, cron jobs and timers, local users, installed packages |
| Data stores | Redis, MySQL and PostgreSQL health facts. Query text is stripped of string and number literals before it leaves the host. |
| Web | Request and error rates from web server access logs |

Some code comments refer to "OHS" rules. That is the Opservo Health Standard,
the rule set the API uses to score the facts this agent reports.

What the agent does **not** do:

- It never reads application `.env` files or other application secrets.
  Database facts use local socket / peer authentication, or a monitoring
  credential file you create yourself (`/etc/infrapilot/mysql.cnf`,
  `/etc/infrapilot/pg.conf`).
- It opens no inbound ports. All traffic is outbound HTTPS to the API.

Secrets in log lines are masked on the host before anything is buffered or
sent (`collectors/redact.go`): URL credentials, Authorization/Bearer values,
known token formats (JWT, AWS, GitHub, GitLab, Slack, Stripe, OpenAI,
Anthropic, Google, SendGrid, npm), `key=value` / JSON / PHP-array secrets,
`--password` flags, `mysql -p`, PEM private keys, email addresses and long
opaque strings. IP addresses, ports and paths are kept, because they are what
explains an error. Masking is pattern-based: a secret in a format it doesn't
recognise can still get through, so don't log secrets.

## How it talks to the API

- **Registration.** On first start the agent registers with an enrollment
  token from the dashboard and receives an agent ID and a secret key, stored in
  `/etc/infrapilot/config`.
- **Heartbeats.** Each payload is HMAC-SHA256 signed with the agent's secret
  key (`X-Agent-ID`, `X-Signature`, `X-Timestamp` headers). The API rejects
  unsigned or wrongly signed payloads.
- **Offline buffer.** If the API cannot be reached, recent heartbeats are kept
  in a local SQLite file and replayed, one per heartbeat, once the API is back.
- **TLS.** Certificates are verified. `--dev` turns verification off and is
  for local development only.

## Remote actions (commands from the dashboard)

The dashboard can run a shell command on a server, for example "restart this
service". How this is controlled:

- The agent polls the API for queued commands (default every 5 seconds) over
  the same outbound HTTPS connection. Nothing connects in to the server.
- The API only queues commands for a server whose remote actions have been
  switched on in the dashboard.
- Every command is signed by the API with an Ed25519 key. The agent checks the
  signature (public key embedded in `executor/executor.go`) and refuses
  unsigned or altered commands. The expiry time is part of the signed
  message; the API stops handing out a command once it has expired.
- Commands run with `sh -c` as the agent's user, in their own process group,
  with a timeout and 64 KB output cap. The command and its output are recorded
  in the workspace's audit log.
- **To turn command polling off completely on a host**, set
  `OPSERVO_ENABLE_ACTIONS=false` in `/etc/infrapilot/config` (or pass
  `--enable-actions=false`) and restart the agent. The agent then never asks
  for commands, whatever the dashboard says.

## Private-network uptime probes (opt-in)

A server can run TCP uptime checks against private targets (for example a
database that is not reachable from the internet). This is **off by default**.
Turn it on per server with `OPSERVO_ENABLE_PROBES=true`. Probe assignments are
Ed25519-signed by the API and checked before the agent connects anywhere. A
probe only opens a TCP connection and closes it; at most 20 checks per agent.

## Install

The normal way is from the dashboard: **Add Server** gives you a one-line
command with an enrollment token, for example:

```bash
curl -sSL https://api.getopservo.com/install.sh | sudo env OPSERVO_TOKEN=<token> bash
```

`install.sh` in this repository is that installer. It detects the CPU
architecture, downloads the binary, verifies the signed manifest (see below),
writes `/etc/infrapilot/config`, and installs the `infrapilot-agent` systemd
unit. (The `infrapilot` names are from the product's earlier name and are kept
so existing installs keep working.)

Useful commands after install:

```bash
systemctl status infrapilot-agent
journalctl -u infrapilot-agent -f
```

### Kubernetes

`cmd/k8s-agent` is a separate binary for clusters. It runs as a single
Deployment replica with a read-only ClusterRole, as non-root, with a read-only
root filesystem. The manifest is in `deploy/kubernetes/opservo-agent.yaml`; the
dashboard serves a copy with your token filled in.

## Build from source

Requires Go 1.25 or newer.

```bash
go build -o bin/opservo-agent .            # Linux agent
go build -o bin/opservo-k8s-agent ./cmd/k8s-agent
go test ./...
```

Cross-compile with `make build-all`. Run against a local API with:

```bash
go run . --dev --api-url http://localhost:3001
```

Main flags (each has an environment variable; legacy `INFRAPILOT_*` names are
also accepted):

| Flag | Env | Default |
|------|-----|---------|
| `--api-url` | `OPSERVO_API_URL` | `https://api.getopservo.com` |
| `--agent-id` | `OPSERVO_AGENT_ID` | set at registration |
| `--secret-key` | `OPSERVO_SECRET_KEY` | set at registration |
| `--enable-actions` | `OPSERVO_ENABLE_ACTIONS` | `true` (polling; see above) |
| `--enable-probes` | `OPSERVO_ENABLE_PROBES` | `false` |
| `--auto-update` | `OPSERVO_AUTO_UPDATE` | `true` |
| `--interval` | | `60s` |

## Updates and signing

The agent updates itself. Once an hour it fetches `/download/manifest.json`
from the API, which lists the SHA-256 of each published binary. If its own
binary differs, it downloads the new one, checks the hash, swaps it in
atomically and restarts in place.

The manifest is signed with an Ed25519 key that is kept offline and used only
at build time (`cmd/sign`). The matching public key is embedded in
`updater/updater.go`, and the agent refuses any update whose manifest signature
does not verify. `install.sh` checks the same signature on first install. So a
compromised API server alone cannot push a modified binary.

If you build the agent yourself, your binary's hash will not match the
published manifest, and auto-update will replace it with the official build.
Run self-built agents with `--auto-update=false` (or
`OPSERVO_AUTO_UPDATE=false`).

Embedded public keys:

- `updater/updater.go` — update manifest signing key.
- `executor/executor.go` and `prober/prober.go` — command and probe signing
  key (one key, with separate message formats for each use).

## Support

- Product and docs: https://getopservo.com
- Questions: hello@getopservo.com
- Security reports: see [SECURITY.md](SECURITY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
