package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/getopservo/opservo-agent/collectors"
	"github.com/getopservo/opservo-agent/reqsign"
)

// robustTransport reconnects cleanly after an API blip (e.g. a deploy recreating
// the container). The default transport keeps idle connections for 90s, so a
// stale/half-open connection gets reused across the 60s heartbeat gap and the
// agent keeps failing for minutes. A short IdleConnTimeout (< the heartbeat
// interval) means each heartbeat opens a fresh connection, and ResponseHeaderTimeout
// makes a dead origin fail fast instead of hanging.

// StatusError is returned by SendRaw when the API answers with a non-2xx
// status, so callers can branch on the code (e.g. a 429 must not be buffered
// for replay — replaying a rate-limited heartbeat only re-trips the limit).
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("api returned status %d", e.Code) }

func robustTransport(devMode bool) *http.Transport {
	t := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       20 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	// Dev only: accept a self-signed API cert (e.g. https://localhost). Gated
	// SOLELY by the --dev flag — never an env var — so a production build cannot
	// accidentally disable TLS verification.
	if devMode {
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- dev-only, flag-gated
	}
	return t
}

// Sender handles all communication with the Opservo API.
type Sender struct {
	apiURL    string
	agentID   string
	secretKey string
	client    *http.Client
}

// New creates a Sender. If devMode, TLS verification is relaxed (dev only).
func New(apiURL, agentID, secretKey string, devMode bool) *Sender {
	if devMode {
		slog.Warn("TLS certificate verification DISABLED — dev mode only")
	}
	return &Sender{
		apiURL:    apiURL,
		agentID:   agentID,
		secretKey: secretKey,
		// Short-lived idle connections so a deploy/API blip recovers on the next
		// heartbeat instead of clinging to a stale connection for minutes.
		client: &http.Client{Timeout: 15 * time.Second, Transport: robustTransport(devMode)},
	}
}

// Send POSTs a heartbeat payload to the API with HMAC signature.
func (s *Sender) Send(ctx context.Context, payload *collectors.Payload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	_, err = s.SendRaw(ctx, body)
	return err
}

// SendRaw POSTs already-marshaled heartbeat bytes, HMAC-signing the exact bytes.
// Used both for a fresh heartbeat and to flush a payload buffered from a prior
// failed send, so the signature always covers the stored bytes.
// Returns the response body — the API may hand back work in it (e.g. signed
// probe assignments for opted-in agents).
func (s *Sender) SendRaw(ctx context.Context, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost,
		s.apiURL+"/api/v1/agents/"+s.agentID+"/heartbeat",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", s.agentID)
	// v2 HMAC: timestamp + nonce bound into the signature (reqsign).
	reqsign.Apply(req.Header, s.secretKey, body)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		if resp.StatusCode == http.StatusUnauthorized {
			// Distinguish "clock is off" (fixable with NTP) from a bad key.
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			reqsign.WarnClockSkew(resp.StatusCode, errBody, "heartbeat")
		}
		return nil, &StatusError{Code: resp.StatusCode}
	}

	// Bounded read: the response is a small JSON ack (possibly with probe
	// assignments); never slurp an unexpectedly huge body.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, nil // sent fine; an unreadable ack body is not a send failure
	}
	return respBody, nil
}

// Register calls the API to get an agent ID and secret key. enrollmentToken
// may be empty (dev) or a single-use ipk_… / multi-use fleet_… token; machineID
// should be collectors.InstanceIdentity() (falls back to MachineID() if empty).
func Register(apiURL, agentVersion string, devMode bool, enrollmentToken, machineID string) (agentID, secretKey string, err error) {
	if machineID == "" {
		machineID = collectors.MachineID()
	}
	return RegisterKind(apiURL, agentVersion, devMode, enrollmentToken, machineID, getHostname(), "")
}

// RegisterKind is Register with an explicit display hostname and agent kind
// ("" = linux, the default; "kubernetes" for the cluster agent, whose
// "hostname" is the cluster name). Behaviour for the Linux agent is unchanged.
func RegisterKind(apiURL, agentVersion string, devMode bool, enrollmentToken, machineID, hostname, kind string) (agentID, secretKey string, err error) {
	fields := map[string]string{
		"hostname":      hostname,
		"agent_version": agentVersion,
		"machine_id":    machineID,
	}
	if kind != "" {
		fields["kind"] = kind
	}
	if enrollmentToken != "" {
		fields["enrollment_token"] = enrollmentToken
	}
	body, _ := json.Marshal(fields)

	client := &http.Client{Timeout: 10 * time.Second, Transport: robustTransport(devMode)}
	resp, err := client.Post(apiURL+"/api/v1/agents/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("registration request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	var result struct {
		AgentID   string `json:"agent_id"`
		SecretKey string `json:"secret_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("decode registration response: %w", err)
	}

	return result.AgentID, result.SecretKey, nil
}

func getHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}
