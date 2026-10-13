package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/getopservo/opservo-agent/buffer"
	"github.com/getopservo/opservo-agent/collectors"
	"github.com/getopservo/opservo-agent/executor"
	"github.com/getopservo/opservo-agent/prober"
	"github.com/getopservo/opservo-agent/sender"
	"github.com/getopservo/opservo-agent/shell"
	"github.com/getopservo/opservo-agent/updater"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

var (
	apiURL         = flag.String("api-url", getEnv("OPSERVO_API_URL", "INFRAPILOT_API_URL", "https://api.getopservo.com"), "Opservo API URL")
	agentID        = flag.String("agent-id", getEnv("OPSERVO_AGENT_ID", "INFRAPILOT_AGENT_ID", ""), "Agent ID (assigned at registration)")
	secretKey      = flag.String("secret-key", getEnv("OPSERVO_SECRET_KEY", "INFRAPILOT_SECRET_KEY", ""), "Agent secret key")
	devMode        = flag.Bool("dev", false, "Development mode (verbose logging, skip TLS verify)")
	interval       = flag.Duration("interval", 60*time.Second, "Heartbeat interval")
	autoUpdate     = flag.Bool("auto-update", getEnv("OPSERVO_AUTO_UPDATE", "INFRAPILOT_AUTO_UPDATE", "true") != "false", "Self-update the agent binary from the API")
	updateInterval = flag.Duration("update-interval", time.Hour, "How often to check for agent updates")
	bufferPath     = flag.String("buffer-path", getEnv("OPSERVO_BUFFER_PATH", "INFRAPILOT_BUFFER_PATH", defaultBufferPath()), "Path to the local SQLite buffer")
	// SECURITY: remote command execution is CLOUD-CONTROLLED. The agent polls by
	// default (so a fleet update makes every server ready with no per-box work),
	// but a server only ever RUNS a command when its `actions_enabled` flag is
	// turned on in the dashboard — the API refuses to dispatch otherwise. Set
	// OPSERVO_ENABLE_ACTIONS=false as a hard, local kill-switch on a box that
	// must never accept commands regardless of the dashboard.
	enableActions  = flag.Bool("enable-actions", getEnv("OPSERVO_ENABLE_ACTIONS", "INFRAPILOT_ENABLE_ACTIONS", "true") != "false", "Poll for dashboard-dispatched commands (execution still gated server-side; set false to hard-disable on this host)")
	actionInterval = flag.Duration("action-interval", 5*time.Second, "How often to poll for dispatched commands")
	// SECURITY: agent-based uptime probes (TCP checks against private-network
	// targets, run from this box) are OFF unless the operator opts this server
	// in locally. A fleet-wide agent update never makes a server probe anything.
	// Assignments must also carry a valid API signature (see prober package).
	enableProbes = flag.Bool("enable-probes", getEnv("OPSERVO_ENABLE_PROBES", "INFRAPILOT_ENABLE_PROBES", "false") == "true", "Run dashboard-assigned private-network TCP uptime checks from this server (opt-in)")
	// SECURITY: live terminal sessions (B-6) are OFF unless the operator sets
	// OPSERVO_ENABLE_SHELL=true on this server — unlike remote actions, the
	// local switch defaults OFF, so a fleet update never gives any server an
	// interactive shell. The dashboard's per-server switch must ALSO be on,
	// remote actions must not be hard-disabled here, and every session start
	// must carry a valid API signature (see the shell package).
	enableShell = flag.Bool("enable-shell", getEnv("OPSERVO_ENABLE_SHELL", "INFRAPILOT_ENABLE_SHELL", "false") == "true", "Allow live terminal sessions opened from the dashboard (opt-in; needs remote actions too)")
)

// defaultBufferPath returns a per-user location for the agent's SQLite buffer.
func defaultBufferPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".infrapilot", "agent-buffer.db")
	}
	return filepath.Join(os.TempDir(), "infrapilot-agent-buffer.db")
}

func main() {
	flag.Parse()

	logLevel := slog.LevelInfo
	if *devMode {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	slog.Info("Opservo agent starting",
		"version", version,
		"api_url", *apiURL,
		"interval", *interval,
		"dev_mode", *devMode,
	)

	// AMI-clone detection (see clonedetect.go). The installer records this
	// box's identity; if the live identity differs, we're a clone booted from
	// an image of another server and must NOT reuse its credentials.
	enrollKey := getEnv("OPSERVO_ENROLL_KEY", "INFRAPILOT_ENROLL_KEY", "")
	recordedIdentity := getEnv("OPSERVO_MACHINE_ID", "INFRAPILOT_MACHINE_ID", "")
	configPath := getEnv("OPSERVO_CONFIG_PATH", "INFRAPILOT_CONFIG_PATH", "/etc/infrapilot/config")
	currentIdentity := collectors.InstanceIdentity()
	if *agentID != "" && isClone(recordedIdentity, currentIdentity) {
		if enrollKey != "" {
			slog.Info("Machine identity changed — this looks like an AMI/template clone; registering as a new server",
				"recorded", recordedIdentity, "current", currentIdentity)
			id, key, err := sender.Register(*apiURL, version, *devMode, enrollKey, currentIdentity)
			if err != nil {
				// Exit → systemd restarts us in 5s; boot-time networking races resolve themselves.
				slog.Error("Clone re-registration failed", "error", err)
				os.Exit(1)
			}
			*agentID = id
			*secretKey = key
			if err := persistIdentity(configPath, id, key, currentIdentity); err != nil {
				slog.Warn("Could not persist new identity — will re-register on next restart", "error", err)
			} else {
				slog.Info("Re-registered as a new server", "agent_id", id)
			}
		} else {
			slog.Warn("Machine identity changed but no fleet enrollment key is configured — "+
				"continuing with the INHERITED identity. If this instance was launched from an AMI of "+
				"another server, both now report as the same server. Create a fleet key in the dashboard "+
				"(Add Server → Auto Scaling) and reinstall, or bake AMIs before installing the agent.",
				"recorded", recordedIdentity, "current", currentIdentity)
		}
	}

	// If no agent ID, register first
	if *agentID == "" || *secretKey == "" {
		slog.Info("No agent credentials found — registering with API")
		id, key, err := sender.Register(*apiURL, version, *devMode, enrollKey, currentIdentity)
		if err != nil {
			slog.Error("Registration failed", "error", err)
			os.Exit(1)
		}
		*agentID = id
		*secretKey = key
		slog.Info("Registration successful", "agent_id", id)
		// The secret key is only echoed in --dev mode: in production logs end up in
		// journald and log shippers. (The installer persists both values to
		// /etc/infrapilot/config itself, so a normal install never relies on this.)
		if *devMode {
			slog.Info("Add these to your environment to skip registration on restart",
				"OPSERVO_AGENT_ID", id,
				"OPSERVO_SECRET_KEY", key,
			)
		} else {
			slog.Info("Persist OPSERVO_AGENT_ID and OPSERVO_SECRET_KEY in "+configPath+" to skip registration on restart — the secret is not logged outside --dev; install with install.sh to have it persisted for you",
				"OPSERVO_AGENT_ID", id,
			)
		}
	}

	// Open the local SQLite buffer (used for per-file log cursors and content
	// dedup). If it cannot be opened, the agent still runs — the logs collector
	// just degrades to best-effort tailing without cross-heartbeat dedup.
	var buf *buffer.Buffer
	if err := os.MkdirAll(filepath.Dir(*bufferPath), 0o755); err != nil {
		slog.Warn("could not create buffer directory", "error", err)
	}
	buf, err := buffer.Open(*bufferPath)
	if err != nil {
		slog.Warn("could not open local buffer — running without log dedup", "error", err)
		buf = nil
	} else {
		defer buf.Close()
		slog.Info("Local buffer ready", "path", *bufferPath)
	}

	// Build collector registry
	registry := collectors.NewRegistry([]collectors.Collector{
		collectors.NewSystemCollector(),
		collectors.NewProcessCollector(),
		collectors.NewServiceCollector(),
		collectors.NewNetworkCollector(),
		collectors.NewAppDetectCollector(),
		collectors.NewDomainCollector(),
		collectors.NewLogsCollector(buf),
		collectors.NewSecurityCollector(),
		collectors.NewStorageCollector(),
		collectors.NewReliabilityCollector(),
		collectors.NewConfigurationCollector(),
		collectors.NewRuntimeCollector(),
		collectors.NewUpdatesCollector(),
		collectors.NewScheduledCollector(),
		collectors.NewUsersCollector(),
		collectors.NewPackagesCollector(),
		collectors.NewActionsCollector(*enableActions, *enableActions && *enableShell, shell.LoginUsers),
		collectors.NewProbesCollector(*enableProbes),
		collectors.NewAgentInfoCollector(version),
		collectors.NewWebMetricsCollector(),
		collectors.NewContainersCollector(),
		collectors.NewRedisCollector(),
		collectors.NewMySQLCollector(),
		collectors.NewPostgresCollector(),
	})

	// Build sender
	s := sender.New(*apiURL, *agentID, *secretKey, *devMode)

	// Run heartbeat loop
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Keep the agent current with no manual re-install. Disabled in dev mode
	// (the binary is a throwaway `go run` build there).
	if *autoUpdate && !*devMode {
		slog.Info("auto-update enabled", "interval", *updateInterval)
		go updater.New(*apiURL, *updateInterval).Run(ctx)
	}

	// Remote command polling — on unless hard-disabled locally; the API only
	// dispatches to servers with actions switched on in the dashboard.
	if *enableActions {
		ex := executor.New(*apiURL, *agentID, *secretKey, *actionInterval)
		if *enableShell {
			slog.Warn("LIVE TERMINAL ENABLED — owners/admins can open a shell on this server from the dashboard when its terminal switch is on",
				"agent_id", *agentID)
			ex = ex.WithShell(shell.NewManager(*apiURL, *agentID, *secretKey, executor.CommandSigningPublicKeyHex(), *devMode))
		}
		go ex.Run(ctx)
	} else if *enableShell {
		slog.Warn("OPSERVO_ENABLE_SHELL is set but remote actions are hard-disabled here (OPSERVO_ENABLE_ACTIONS=false) — live terminal stays off")
	}

	// Agent-based uptime probes — only when explicitly opted in on this server.
	var prb *prober.Prober
	if *enableProbes {
		slog.Warn("PROBES ENABLED — this server will run dashboard-assigned private-network TCP checks",
			"agent_id", *agentID)
		prb = prober.New(*agentID)
	}

	slog.Info("Agent running — sending heartbeats", "interval", *interval)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	// Send immediately on start
	sendHeartbeat(ctx, registry, s, buf, prb)

	for {
		select {
		case <-ticker.C:
			sendHeartbeat(ctx, registry, s, buf, prb)
		case <-ctx.Done():
			slog.Info("Agent shutting down")
			return
		}
	}
}

// maxPendingHeartbeats bounds how many outage-buffered heartbeats we retain +
// replay, so a long outage backfills recent history without growing forever.
const maxPendingHeartbeats = 15

// maxBackfillPerTick caps how many buffered heartbeats are replayed after one
// successful live send. The API rate-limits heartbeats per agent (fixed
// 60 s window); replaying the whole backlog at once pushed a recovering agent
// over that limit, the rejected LIVE heartbeat was buffered again, and the
// backlog never drained (every other heartbeat 429'd for good). One replay per tick keeps a recovering agent at
// 2 requests/min, well under the API's cap.
const maxBackfillPerTick = 1

func sendHeartbeat(ctx context.Context, registry *collectors.Registry, s *sender.Sender, buf *buffer.Buffer, prb *prober.Prober) {
	payload, err := registry.CollectAll(ctx)
	if err != nil {
		slog.Error("Collection failed", "error", err)
		return
	}
	// Include last round's probe results (drained even if this send fails —
	// stale reachability results are worthless, unlike metrics).
	if prb != nil {
		if results := prb.Drain(); len(results) > 0 {
			payload.Data["check_results"] = results
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Heartbeat marshal failed", "error", err)
		return
	}
	resp, err := s.SendRaw(ctx, body)
	if err != nil {
		slog.Error("Heartbeat send failed", "error", err)
		// Buffer this interval's data so a brief API outage/deploy doesn't lose it;
		// it's replayed on the next successful send. A 429 is the one
		// failure NOT worth buffering: the API already has fresher data and
		// replaying it would just trip the limit again.
		if buf != nil && !isRateLimited(err) {
			if e := buf.EnqueueHeartbeat(body, maxPendingHeartbeats); e != nil {
				slog.Debug("could not buffer heartbeat", "error", e)
			}
		}
		return
	}
	slog.Debug("Heartbeat sent successfully")
	// The response may hand back signed probe assignments for this round.
	if prb != nil && len(resp) > 0 {
		var ack struct {
			Checks []prober.Check `json:"checks"`
		}
		if json.Unmarshal(resp, &ack) == nil && len(ack.Checks) > 0 {
			prb.Run(ack.Checks)
		}
	}
	if buf != nil {
		flushPending(ctx, s, buf)
	}
}

// flushPending replays heartbeats buffered during a prior outage, oldest-first,
// stopping at the first failure so the remainder is retried next time.
func flushPending(ctx context.Context, s *sender.Sender, buf *buffer.Buffer) {
	pend, err := buf.PendingHeartbeats(maxBackfillPerTick)
	if err != nil || len(pend) == 0 {
		return
	}
	sent := 0
	for _, p := range pend {
		if _, err := s.SendRaw(ctx, p.Payload); err != nil {
			break // API down again — keep the rest for the next successful send
		}
		_ = buf.DeleteHeartbeat(p.ID)
		sent++
	}
	if sent > 0 {
		slog.Info("backfilled buffered heartbeats", "count", sent)
	}
}

// isRateLimited reports whether a send failed because the API rate-limited us.
func isRateLimited(err error) bool {
	var se *sender.StatusError
	return errors.As(err, &se) && se.Code == http.StatusTooManyRequests
}

// getEnv reads newKey first, then oldKey (backward compat for agents installed
// with the legacy INFRAPILOT_* variables), then the fallback default.
func getEnv(newKey, oldKey, fallback string) string {
	if v := os.Getenv(newKey); v != "" {
		return v
	}
	if v := os.Getenv(oldKey); v != "" {
		return v
	}
	return fallback
}
