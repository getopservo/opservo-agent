#!/usr/bin/env bash
#
# Opservo agent installer.
#
#   curl -sSL https://api.getopservo.com/install.sh | sudo env OPSERVO_TOKEN=<token> bash
#
#   (the dashboard's "Add Server" flow gives you this exact command)
#
#   Prefer to keep the token out of your shell history and `ps`? Add --prompt
#   and the installer asks for it on the terminal (not echoed):
#
#   curl -sSL https://api.getopservo.com/install.sh | sudo bash -s -- --prompt
#
# What it does:
#   1. Detects the Linux distro + CPU architecture.
#   2. Downloads the matching agent binary from the Opservo API (or
#      OPSERVO_BINARY_BASE) and verifies its Ed25519-signed manifest.
#   3. Writes /etc/infrapilot/config (API URL + agent credentials).
#   4. Installs a systemd unit that runs on boot and restarts on failure.
#   5. Starts the agent immediately.
#   6. Prints the agent ID and a link to the dashboard.
#
# It is safe to re-run: existing credentials are reused (the binary is just
# upgraded in place). Everything is configurable via environment variables so
# the one-liner can be customised without editing the script:
#
#   OPSERVO_API_URL        API base URL        (default https://api.getopservo.com)
#   OPSERVO_DASHBOARD_URL  Dashboard base URL  (optional; derived from API URL)
#   OPSERVO_VERSION        Release to install  (default "latest")
#   OPSERVO_TENANT_ID      Tenant to register under (optional)
#   OPSERVO_TOKEN          Enrollment token from the dashboard "Add Server" flow
#   OPSERVO_AGENT_ID       Pre-provisioned agent ID  (optional; skips registration)
#   OPSERVO_SECRET_KEY     Pre-provisioned secret key (optional; with AGENT_ID)
#   OPSERVO_FORCE          Set to 1 to re-register even if creds already exist.
#   OPSERVO_OPENSSL_BIN    OpenSSL binary used for Ed25519 signature verification
#                          (needs OpenSSL 3.x; auto-probes `openssl`/`openssl3`,
#                          then falls back to a pure-python3 verifier — so old
#                          hosts like Ubuntu 20.04 need no override at all)
#   (legacy INFRAPILOT_* variables are still accepted for backward compatibility)
#
set -euo pipefail

# ── Configuration (env-overridable) ──────────────────────────────────────────
# Accept OPSERVO_* (current), falling back to the legacy INFRAPILOT_* names so
# older install commands / re-installs keep working.
API_URL="${OPSERVO_API_URL:-${INFRAPILOT_API_URL:-https://api.getopservo.com}}"
# Refuse a manually-overridden http:// API URL — the agent's secret key and
# every heartbeat would go over plaintext. Only http://localhost/127.0.0.1 is
# allowed, for local dev against a non-TLS API.
case "${API_URL}" in
  http://*)
    case "${API_URL}" in
      http://localhost*|http://127.0.0.1*) : ;;
      *)
        echo "Error: OPSERVO_API_URL must be https:// (got: ${API_URL})" >&2
        echo "       Plaintext http:// would send the agent's secret key unencrypted." >&2
        exit 1
        ;;
    esac
    ;;
esac
# If the dashboard URL is not given, derive it from the API URL (drop an "-api"
# or "api." from the host), so the printed link points at the real dashboard.
DASHBOARD_URL="${OPSERVO_DASHBOARD_URL:-${INFRAPILOT_DASHBOARD_URL:-}}"
if [ -z "${DASHBOARD_URL}" ]; then
  DASHBOARD_URL="$(printf '%s' "${API_URL}" | sed -E 's#-api\.#.#; s#//api\.#//#')"
fi
VERSION="${OPSERVO_VERSION:-${INFRAPILOT_VERSION:-latest}}"
TENANT_ID="${OPSERVO_TENANT_ID:-${INFRAPILOT_TENANT_ID:-}}"
ENROLLMENT_TOKEN="${OPSERVO_TOKEN:-${INFRAPILOT_TOKEN:-}}"   # from the dashboard "Add New Server" flow
PROMPT_TOKEN=0   # --prompt: read the token from the terminal instead of the environment
FORCE="${OPSERVO_FORCE:-${INFRAPILOT_FORCE:-0}}"
UNINSTALL="${OPSERVO_UNINSTALL:-${INFRAPILOT_UNINSTALL:-0}}"  # set to 1 to remove the agent instead

BINARY_NAME="infrapilot-agent"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
# Ed25519 public key (hex) that signs the update manifest. Must match
# agent/updater/updater.go:signingPublicKeyHex. When set, the installer REFUSES
# to install a binary whose signed manifest can't be verified — so a compromised
# distribution server alone can't push a trojanised agent (it lacks the offline
# signing key). Empty = signature checking disabled (legacy behaviour).
AGENT_SIGNING_PUBKEY="${OPSERVO_SIGNING_PUBKEY:-b7f1a9b29bd8ea7982a3e21b39a119ca4dbdfd065cf7bcdba486487d0bb0bc76}"
CONFIG_DIR="/etc/infrapilot"
CONFIG_FILE="${CONFIG_DIR}/config"
UNIT_FILE="/etc/systemd/system/infrapilot-agent.service"
STATE_DIR="/var/lib/infrapilot"
BUFFER_PATH="${STATE_DIR}/agent-buffer.db"

TMP_DIR=""
cleanup() { [ -n "${TMP_DIR}" ] && rm -rf "${TMP_DIR}" 2>/dev/null || true; }
trap cleanup EXIT

# ── Pretty output ─────────────────────────────────────────────────────────────
if [ -t 1 ]; then
  C_RESET=$'\033[0m'; C_BLUE=$'\033[34m'; C_GREEN=$'\033[32m'
  C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_BOLD=$'\033[1m'
else
  C_RESET=""; C_BLUE=""; C_GREEN=""; C_RED=""; C_YELLOW=""; C_BOLD=""
fi
info()    { printf '%s==>%s %s\n' "${C_BLUE}" "${C_RESET}" "$*"; }
success() { printf '%s✓%s %s\n'  "${C_GREEN}" "${C_RESET}" "$*"; }
warn()    { printf '%s!%s %s\n'   "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
fail()    { printf '%sError:%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; exit 1; }

# hex_to_bin — read hex (whitespace ignored) from stdin, emit raw bytes. Uses
# only bash + printf so we don't depend on xxd/perl being present.
hex_to_bin() {
  local h; h="$(cat)"; h="${h//[[:space:]]/}"
  [ -n "${h}" ] || return 1
  printf "$(printf '%s' "${h}" | sed -e 's/../\\x&/g')"
}

# ── Privilege handling ────────────────────────────────────────────────────────
# Run privileged steps via $SUDO so the one-liner works as a non-root user too.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    printf '%sError:%s This installer needs root privileges, and sudo is not available.\n\n' "${C_RED}" "${C_RESET}" >&2
    printf 'The Opservo agent needs root to install a system service. It cannot run on\n' >&2
    printf 'shared hosting (Hostinger, GoDaddy, Bluehost, cPanel plans) where root is not\n' >&2
    printf 'offered. You have two options:\n\n' >&2
    printf '  1. Monitor this site without an agent: in Opservo, open Uptime and add an\n' >&2
    printf '     HTTP monitor for the URL and a Domain monitor for SSL expiry. No install needed.\n' >&2
    printf '  2. For the full agent (services, logs, AI fixes), use a VPS or dedicated\n' >&2
    printf '     server where you have root, then re-run this command there.\n\n' >&2
    printf 'If this IS your own server, re-run the same command as root (e.g. via "su -").\n' >&2
    exit 1
  fi
fi

# write_file <path> <mode>  — reads file content from stdin, writes it as root.
write_file() {
  local path="$1" mode="$2"
  $SUDO install -m "${mode}" /dev/null "${path}"
  $SUDO tee "${path}" >/dev/null
  $SUDO chmod "${mode}" "${path}"
}

# ── Step 1: detect distro + arch ──────────────────────────────────────────────
detect_platform() {
  [ "$(uname -s)" = "Linux" ] || fail "Opservo only supports Linux (found $(uname -s))."

  # Source os-release in a subshell so its variables (NAME, VERSION, ID, …) do
  # not clobber our own (notably VERSION, which is the release to install).
  local distro="unknown"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    distro="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-${NAME:-${ID:-unknown}}}")"
    [ -n "${distro}" ] || distro="unknown"
  fi

  case "$(uname -m)" in
    x86_64 | amd64) ARCH="amd64" ;;
    aarch64 | arm64) ARCH="arm64" ;;
    *) fail "Unsupported architecture: $(uname -m). Opservo supports amd64 and arm64." ;;
  esac

  [ -d /run/systemd/system ] || fail "systemd is required but was not detected on this host."
  command -v curl >/dev/null 2>&1 || fail "curl is required but was not found."

  info "Detected ${C_BOLD}${distro}${C_RESET} on ${C_BOLD}${ARCH}${C_RESET}"
}

# openssl_can_verify_ed25519 <openssl_bin>
# True when the given openssl can round-trip an Ed25519 raw sign+verify.
# `pkeyutl -verify -rawin` needs OpenSSL 3.x — 1.1.x (e.g. Ubuntu 20.04's
# 1.1.1f) can sign but not verify raw-input Ed25519, so we prove the full
# round trip on a throwaway key instead of trusting the version string.
openssl_can_verify_ed25519() {
  local bin="$1" d="${TMP_DIR}/ossl-selftest"
  mkdir -p "${d}" || return 1
  printf 'opservo-selftest' > "${d}/msg"
  "${bin}" genpkey -algorithm ed25519 -out "${d}/key.pem" >/dev/null 2>&1 \
    && "${bin}" pkey -in "${d}/key.pem" -pubout -out "${d}/pub.pem" >/dev/null 2>&1 \
    && "${bin}" pkeyutl -sign -rawin -inkey "${d}/key.pem" -in "${d}/msg" -out "${d}/sig" >/dev/null 2>&1 \
    && "${bin}" pkeyutl -verify -rawin -pubin -inkey "${d}/pub.pem" -in "${d}/msg" -sigfile "${d}/sig" >/dev/null 2>&1
}

# pick_openssl — echo the first openssl binary able to verify Ed25519.
# Honors OPSERVO_OPENSSL_BIN (that exact binary or nothing), then probes
# `openssl` and `openssl3` from PATH. Returns 1 if none qualifies.
pick_openssl() {
  # NOTE: runs inside $(…), so warn (stderr) is visible but fail would only
  # kill the subshell — the caller does the actual fail.
  local override="${OPSERVO_OPENSSL_BIN:-${INFRAPILOT_OPENSSL_BIN:-}}"
  if [ -n "${override}" ]; then
    if ! command -v "${override}" >/dev/null 2>&1; then
      warn "OPSERVO_OPENSSL_BIN is set to '${override}' but it was not found."
      return 1
    fi
    if ! openssl_can_verify_ed25519 "${override}"; then
      warn "OPSERVO_OPENSSL_BIN ('${override}', $("${override}" version 2>/dev/null)) cannot verify Ed25519 signatures — it must be OpenSSL 3.x."
      return 1
    fi
    printf '%s' "${override}"
    return 0
  fi
  local candidate
  for candidate in openssl openssl3; do
    command -v "${candidate}" >/dev/null 2>&1 || continue
    if openssl_can_verify_ed25519 "${candidate}"; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

# ed25519_verify_py3 <pubkey_hex> <msg_file> <sig_file>
# Fallback verifier for hosts whose openssl predates 3.x (e.g. Ubuntu 20.04's
# 1.1.1f, which cannot `pkeyutl -verify -rawin`): a self-contained RFC 8032
# Ed25519 VERIFY in pure python3 stdlib (no pip modules). Verify-only over
# public data — there is no secret here to leak, so the usual constant-time
# concerns of hand-rolled crypto do not apply. Exit 0 = valid signature.
ed25519_verify_py3() {
  python3 - "$1" "$2" "$3" <<'PYEOF'
import sys, hashlib

p = 2**255 - 19
d = -121665 * pow(121666, p - 2, p) % p
q = 2**252 + 27742317777372353535851937790883648493

def recover_x(y, sign):
    if y >= p: return None
    x2 = (y*y - 1) * pow(d*y*y + 1, p - 2, p) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * pow(2, (p - 1) // 4, p) % p
    if (x*x - x2) % p != 0: return None
    if (x & 1) != sign: x = p - x
    return x

def edwards_add(P, Q):
    x1, y1, z1, t1 = P; x2, y2, z2, t2 = Q
    A = (y1 - x1) * (y2 - x2) % p
    B = (y1 + x1) * (y2 + x2) % p
    C = 2 * t1 * t2 * d % p
    D = 2 * z1 * z2 % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E*F % p, G*H % p, F*G % p, E*H % p)

def scalarmult(P, e):
    Q = (0, 1, 1, 0)
    while e > 0:
        if e & 1: Q = edwards_add(Q, P)
        P = edwards_add(P, P)
        e >>= 1
    return Q

def decompress(s):
    if len(s) != 32: return None
    y = int.from_bytes(s, "little")
    x = recover_x(y & ((1 << 255) - 1), y >> 255)
    if x is None: return None
    y &= (1 << 255) - 1
    return (x, y, 1, x * y % p)

def point_equal(P, Q):
    return (P[0]*Q[2] - Q[0]*P[2]) % p == 0 and (P[1]*Q[2] - Q[1]*P[2]) % p == 0

g_y = 4 * pow(5, p - 2, p) % p
g_x = recover_x(g_y, 0)
B = (g_x, g_y, 1, g_x * g_y % p)

def verify(pub, msg, sig):
    if len(sig) != 64 or len(pub) != 32: return False
    A = decompress(pub)
    R = decompress(sig[:32])
    if A is None or R is None: return False
    S = int.from_bytes(sig[32:], "little")
    if S >= q: return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % q
    return point_equal(scalarmult(B, S), edwards_add(R, scalarmult(A, h)))

pub = bytes.fromhex(sys.argv[1])
with open(sys.argv[2], "rb") as f: msg = f.read()
with open(sys.argv[3], "rb") as f: sig = f.read()
sys.exit(0 if verify(pub, msg, sig) else 1)
PYEOF
}

# verify_binary <binary_base> <asset> <downloaded_file>
# Proves the freshly-downloaded binary is authentic before we install it:
#   1. Fetch the update manifest (sha256 of each asset) + its Ed25519 signature.
#   2. When a signing key is embedded, Ed25519-verify the manifest signature —
#      authenticity, not just transport integrity. A compromised server can't
#      forge this without the offline private key. Fails CLOSED.
#   3. Check the downloaded binary's sha256 against the (now trusted) manifest.
verify_binary() {
  local binary_base="$1" asset="$2" out="$3"
  local pubkey_hex="${AGENT_SIGNING_PUBKEY}"
  local man="${TMP_DIR}/manifest.json"

  if ! curl -fsSL --retry 3 --retry-delay 2 -o "${man}" "${binary_base}/manifest.json"; then
    [ -n "${pubkey_hex}" ] && fail "Could not fetch the update manifest to verify the binary — refusing to install."
    warn "No manifest published for this release — skipping verification."
    return 0
  fi

  # ── (1) Authenticity: Ed25519-verify the manifest signature ────────────────
  if [ -n "${pubkey_hex}" ]; then
    local sig_hex="${TMP_DIR}/manifest.json.sig" sig="${TMP_DIR}/manifest.sig.bin" pem="${TMP_DIR}/agent_pub.pem"
    if ! curl -fsSL --retry 3 --retry-delay 2 -o "${sig_hex}" "${binary_base}/manifest.json.sig"; then
      fail "This server's update manifest is not signed — refusing to install (possible tampering or a build without code-signing)."
    fi
    if ! hex_to_bin < "${sig_hex}" > "${sig}"; then
      fail "Agent signature is malformed — refusing to install."
    fi
    local ossl=""
    if ossl="$(pick_openssl)"; then
      # Reconstruct a PEM public key from the raw 32-byte Ed25519 key: the fixed
      # Ed25519 SubjectPublicKeyInfo DER prefix (302a300506032b6570032100) + key.
      {
        echo "-----BEGIN PUBLIC KEY-----"
        printf '302a300506032b6570032100%s' "${pubkey_hex}" | hex_to_bin | "${ossl}" base64
        echo "-----END PUBLIC KEY-----"
      } > "${pem}"
      if ! "${ossl}" pkeyutl -verify -pubin -inkey "${pem}" -rawin -in "${man}" -sigfile "${sig}" >/dev/null 2>&1; then
        fail "Agent signature verification FAILED — refusing to install (the download may be tampered with)."
      fi
      success "Agent signature verified (Ed25519, via ${ossl})"
    elif command -v python3 >/dev/null 2>&1; then
      # Old openssl (1.1.x can't `pkeyutl -verify -rawin`) — same verification,
      # pure-python3 stdlib instead. Still fails closed.
      if ! ed25519_verify_py3 "${pubkey_hex}" "${man}" "${sig}"; then
        fail "Agent signature verification FAILED — refusing to install (the download may be tampered with)."
      fi
      success "Agent signature verified (Ed25519, via python3)"
    else
      fail "Cannot verify the agent signature: your OpenSSL ($(openssl version 2>/dev/null || echo "not found")) is too old for Ed25519 verify (needs 3.x; Ubuntu 20.04 ships 1.1.1) and python3 was not found.
       Install python3, OR install a standalone OpenSSL 3.x and re-run with OPSERVO_OPENSSL_BIN=/path/to/openssl3."
    fi
  fi

  # ── (2) Integrity: binary must match the sha256 the trusted manifest lists ─
  local expected actual
  # `|| true`: grep exits non-zero when the asset is absent; without it `set -e`
  # would abort before the graceful "no checksum" handling below.
  expected="$(grep -o "\"${asset}\"[[:space:]]*:[[:space:]]*\"[0-9a-f]*\"" "${man}" | grep -o '[0-9a-f]\{64\}' | head -1 || true)"
  if [ -z "${expected}" ]; then
    [ -n "${pubkey_hex}" ] && fail "Signed manifest lists no checksum for ${asset} — refusing to install."
    warn "Manifest has no checksum for ${asset} — skipping integrity check."
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${out}" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${out}" | awk '{print $1}')"
  else
    [ -n "${pubkey_hex}" ] && fail "No sha256 tool available to verify the binary — refusing to install."
    warn "No sha256 tool available — skipping integrity check."
    return 0
  fi
  [ "${expected}" = "${actual}" ] || fail "Checksum mismatch — refusing to install (expected ${expected}, got ${actual})."
  success "Checksum verified"
}

# ── Step 2: download the agent binary ─────────────────────────────────────────
download_binary() {
  local asset="${BINARY_NAME}-linux-${ARCH}"
  # By default the binary is served by the Opservo API itself (no GitHub
  # access needed). Override OPSERVO_BINARY_BASE to fetch from elsewhere, or
  # set it to a GitHub releases URL.
  local binary_base="${OPSERVO_BINARY_BASE:-${INFRAPILOT_BINARY_BASE:-${API_URL%/}/download}}"
  local url="${binary_base}/${asset}"

  TMP_DIR="$(mktemp -d)"
  local out="${TMP_DIR}/${asset}"

  info "Downloading ${asset} from ${binary_base}…"
  # Force HTTP/1.1: large downloads over HTTP/2 through a proxy/tunnel can hit
  # "stream not closed cleanly" resets. Retry (restart) a few times on failure.
  if ! curl -fSL --http1.1 --retry 5 --retry-delay 2 --retry-connrefused \
        --connect-timeout 15 -o "${out}" "${url}"; then
    fail "Could not download the agent from ${url}"
  fi
  [ -s "${out}" ] || fail "Downloaded agent binary is empty."

  verify_binary "${binary_base}" "${asset}" "${out}"

  $SUDO install -m 0755 "${out}" "${INSTALL_PATH}"
  success "Installed ${INSTALL_PATH}"
}

# ── Step 3: resolve credentials + write config ────────────────────────────────

# json_field <field> — extracts a string field from a flat JSON object on stdin.
json_field() {
  grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 \
    | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/' || true
}

# Reads an existing value out of the current config file, if present.
config_value() {
  [ -r "${CONFIG_FILE}" ] || return 0
  $SUDO grep -E "^$1=" "${CONFIG_FILE}" 2>/dev/null | head -1 | cut -d= -f2- || true
}

# Per-instance identity — MUST match the order the agent uses in
# collectors.InstanceIdentity() (EC2 IMDSv2 instance-id → DMI board_asset_tag →
# machine-id), because the agent compares the value recorded here against its
# own computation to detect AMI/template clones. A cloud instance id beats
# machine-id: baking an AMI preserves /etc/machine-id, so every Auto Scaling
# clone would share it.
instance_identity() {
  local tok id
  tok="$(curl -sS -m 2 -X PUT http://169.254.169.254/latest/api/token \
        -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)"
  if [ -n "${tok}" ]; then
    id="$(curl -sS -m 2 -H "X-aws-ec2-metadata-token: ${tok}" \
         http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || true)"
    id="$(printf '%s' "${id}" | tr -d '[:space:]')"
    [ -n "${id}" ] && { printf '%s' "${id}"; return 0; }
  fi
  id="$(cat /sys/class/dmi/id/board_asset_tag 2>/dev/null | tr -d '[:space:]')"
  case "${id}" in i-*) printf '%s' "${id}"; return 0 ;; esac
  id="$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || cat /sys/class/dmi/id/product_uuid 2>/dev/null || echo '')"
  printf '%s' "${id}" | tr -d '[:space:]'
}

# register_agent [soft]
#   Registers with the API. With "soft", an API rejection returns 1 (and prints
#   the reason) instead of exiting — used when the box already has credentials
#   to fall back on. When EXISTING_AGENT_ID/EXISTING_SECRET_KEY are set they are
#   sent along so the API can bind the token to this server's existing identity
#   (re-adding to the SAME workspace) instead of creating a duplicate.
register_agent() {
  local soft="${1:-}"
  local hostname payload resp machine_id
  hostname="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"
  # The hostname is interpolated into JSON below: escape the two characters
  # that would break (or inject into) the string literal.
  hostname="${hostname//\\/\\\\}"
  hostname="${hostname//\"/\\\"}"
  # Stable per-instance id so the dashboard can flag the same box enrolled
  # twice, and so the agent can detect AMI clones (see instance_identity).
  machine_id="$(instance_identity)"

  payload="{\"hostname\":\"${hostname}\",\"agent_version\":\"${VERSION}\""
  [ -n "${TENANT_ID}" ] && payload="${payload},\"tenant_id\":\"${TENANT_ID}\""
  [ -n "${ENROLLMENT_TOKEN}" ] && payload="${payload},\"enrollment_token\":\"${ENROLLMENT_TOKEN}\""
  [ -n "${machine_id}" ] && payload="${payload},\"machine_id\":\"${machine_id}\""
  if [ -n "${EXISTING_AGENT_ID:-}" ] && [ -n "${EXISTING_SECRET_KEY:-}" ]; then
    payload="${payload},\"existing_agent_id\":\"${EXISTING_AGENT_ID}\",\"existing_secret_key\":\"${EXISTING_SECRET_KEY}\""
  fi
  payload="${payload}}"

  info "Registering this server with Opservo…" >&2
  # Capture body + status separately (no -f) so we can surface the API's own,
  # actionable error — notably "an enrollment token is required".
  local tmp http body msg
  tmp="$(mktemp)"
  http="$(curl -sSL --retry 3 --connect-timeout 15 -o "${tmp}" -w '%{http_code}' \
    -X POST "${API_URL}/api/v1/agents/register" \
    -H "Content-Type: application/json" \
    -d "${payload}" 2>/dev/null || echo 000)"
  body="$(cat "${tmp}" 2>/dev/null)"; rm -f "${tmp}"

  if [ "${http}" = "000" ]; then
    fail "Could not reach ${API_URL}. Check this server has internet access."
  fi
  if [ "${http}" != "200" ] && [ "${http}" != "201" ]; then
    msg="$(printf '%s' "${body}" | json_field error)"
    if [ "${soft}" = "soft" ]; then
      REGISTER_ERROR="HTTP ${http}: ${msg:-${body}}"
      REGISTER_CODE="$(printf '%s' "${body}" | json_field code)"
      return 1
    fi
    if [ -z "${ENROLLMENT_TOKEN}" ]; then
      # Tokenless install: guide the user to sign up and get their real command.
      printf '\n%s%sThis server needs an enrollment token to join your workspace.%s\n' "${C_BOLD}" "${C_YELLOW}" "${C_RESET}" >&2
      printf '  1. Sign up (free) at %s%s%s\n' "${C_BOLD}" "${DASHBOARD_URL}" "${C_RESET}" >&2
      printf '  2. Open %sAdd New Server%s and copy the one-line command it shows —\n' "${C_BOLD}" "${C_RESET}" >&2
      printf '     it includes your token. Run THAT command here instead.\n' >&2
      fail "No enrollment token provided. ${msg:-Registration was rejected.}"
    fi
    fail "Registration failed (HTTP ${http}): ${msg:-${body}}"
  fi

  AGENT_ID="$(printf '%s' "${body}" | json_field agent_id)"
  SECRET_KEY="$(printf '%s' "${body}" | json_field secret_key)"
  if [ -z "${AGENT_ID}" ] || [ -z "${SECRET_KEY}" ]; then
    fail "Registration did not return credentials. Response: ${body}"
  fi
}

resolve_credentials() {
  # 1. Pre-provisioned via environment (OPSERVO_*, legacy INFRAPILOT_* fallback).
  local env_id env_key
  env_id="${OPSERVO_AGENT_ID:-${INFRAPILOT_AGENT_ID:-}}"
  env_key="${OPSERVO_SECRET_KEY:-${INFRAPILOT_SECRET_KEY:-}}"
  if [ -n "${env_id}" ] && [ -n "${env_key}" ]; then
    AGENT_ID="${env_id}"
    SECRET_KEY="${env_key}"
    info "Using agent credentials from the environment."
    return
  fi

  # 2. Reuse existing config (idempotent re-install / upgrade). Read the current
  # OPSERVO_* keys, falling back to a legacy INFRAPILOT_* config so old boxes
  # keep their identity across the rename.
  if [ "${FORCE}" != "1" ]; then
    local existing_id existing_key
    existing_id="$(config_value OPSERVO_AGENT_ID)";  [ -z "${existing_id}" ]  && existing_id="$(config_value INFRAPILOT_AGENT_ID)"
    existing_key="$(config_value OPSERVO_SECRET_KEY)"; [ -z "${existing_key}" ] && existing_key="$(config_value INFRAPILOT_SECRET_KEY)"
    if [ -n "${existing_id}" ] && [ -n "${existing_key}" ]; then
      case "${ENROLLMENT_TOKEN}" in
        ipk_*)
          # The operator ran a fresh "Add New Server" command on a server that
          # is already registered. Honour the token: the API binds it to this
          # existing identity if it's for the same workspace, or registers a
          # new identity if it's for a different one. Either way the dashboard
          # card that minted the token completes. If the token is spent or
          # expired, keep the existing registration and say so plainly.
          info "This server is already registered as agent ${existing_id}."
          info "An enrollment token was supplied, so joining the workspace it was created in…"
          EXISTING_AGENT_ID="${existing_id}"
          EXISTING_SECRET_KEY="${existing_key}"
          local attempt=0 max_attempts=120   # 120 × 5s = 10 minutes for the user to decide
          while :; do
            if register_agent soft; then
              if [ "${AGENT_ID}" = "${existing_id}" ]; then
                success "Same workspace — kept this server's existing identity; the dashboard will now see it."
              else
                success "Moved: this server now reports to the workspace that generated this command."
                success "Its entry in the previous workspace has been archived there (restorable)."
              fi
              return
            fi
            if [ "${REGISTER_CODE:-}" != "already_registered" ]; then
              break
            fi
            # The server lives in another workspace. The API will not move it
            # until a human confirms in the dashboard window that generated
            # this command — wait for that decision here so the user never has
            # to run anything twice.
            if [ "${attempt}" -eq 0 ]; then
              printf '\n%s%sThis server is already added to another Opservo workspace.%s\n' "${C_BOLD}" "${C_YELLOW}" "${C_RESET}" >&2
              printf '  A server reports to ONE workspace. In the dashboard window that generated this\n' >&2
              printf '  command, choose %sMove it to this workspace%s or %sLeave it where it is%s.\n' "${C_BOLD}" "${C_RESET}" "${C_BOLD}" "${C_RESET}" >&2
              printf '  Waiting for your decision (up to 10 minutes; Ctrl-C keeps the current setup)…\n' >&2
            fi
            attempt=$((attempt + 1))
            if [ "${attempt}" -ge "${max_attempts}" ]; then
              REGISTER_ERROR="no decision within 10 minutes"
              break
            fi
            sleep 5
          done
          # The credentials on disk were issued by the API named in the existing
          # config. If this run targets a DIFFERENT API (e.g. a self-hosted API),
          # falling back to them would write a config that pairs the new URL
          # with an identity that API has never heard of — every heartbeat then
          # 404s forever and the server silently drops out of BOTH dashboards.
          # Refuse instead and leave the working config untouched.
          local existing_url
          existing_url="$(config_value OPSERVO_API_URL)"; [ -z "${existing_url}" ] && existing_url="$(config_value INFRAPILOT_API_URL)"
          if [ -n "${existing_url}" ] && [ "${existing_url%/}" != "${API_URL%/}" ]; then
            printf '\n%s%sThis server is currently registered with %s, not %s.%s\n' "${C_BOLD}" "${C_YELLOW}" "${existing_url}" "${API_URL}" "${C_RESET}" >&2
            printf '  Registering it with %s failed (%s), and its existing credentials are\n' "${API_URL}" "${REGISTER_ERROR:-rejected}" >&2
            printf '  not valid there, so nothing was changed. Generate a fresh "Add New Server"\n' >&2
            printf '  command and run it again once %s is reachable.\n' "${API_URL}" >&2
            fail "Not switching this server to ${API_URL} without a successful registration."
          fi
          warn "Could not use the enrollment token (${REGISTER_ERROR:-rejected})."
          warn "Keeping the existing registration for agent ${existing_id}: this server stays in"
          warn "the workspace it was first added to, and the dashboard's \"Add a new server\""
          warn "window will not complete. To move it, generate a fresh command there and"
          warn "confirm the move when asked."
          AGENT_ID="${existing_id}"
          SECRET_KEY="${existing_key}"
          return
          ;;
      esac
      AGENT_ID="${existing_id}"
      SECRET_KEY="${existing_key}"
      info "Reusing existing agent ${AGENT_ID} (set OPSERVO_FORCE=1 to re-register)."
      return
    fi
  fi

  # 3. Fresh registration.
  register_agent
}

write_config() {
  $SUDO mkdir -p "${CONFIG_DIR}"
  # A re-install must not silently flip a previously opted-in setting back off.
  local probes="false"
  if $SUDO grep -q '^OPSERVO_ENABLE_PROBES=true$' "${CONFIG_FILE}" 2>/dev/null; then
    probes="true"
  fi
  local shell_opt="false"
  if $SUDO grep -q '^OPSERVO_ENABLE_SHELL=true$' "${CONFIG_FILE}" 2>/dev/null; then
    shell_opt="true"
  fi
  # Nor may it drop a local kill-switch (OPSERVO_ENABLE_ACTIONS=false,
  # OPSERVO_AUTO_UPDATE=false) or any other OPSERVO_*/INFRAPILOT_* line the
  # operator added by hand: every existing key the template does not set this
  # run is carried over verbatim, after the template, and named on the way.
  local preserved="" preserved_keys="" line key
  while IFS= read -r line; do
    key="${line%%=*}"
    case "${key}" in
      OPSERVO_API_URL|OPSERVO_AGENT_ID|OPSERVO_SECRET_KEY|OPSERVO_BUFFER_PATH|OPSERVO_ENABLE_PROBES|OPSERVO_ENABLE_SHELL|OPSERVO_MACHINE_ID) continue ;;
      OPSERVO_ENROLL_KEY) case "${ENROLLMENT_TOKEN}" in fleet_*) continue ;; esac ;;
    esac
    preserved="${preserved}
${line}"
    preserved_keys="${preserved_keys}${preserved_keys:+ }${key}"
  done < <($SUDO grep -E '^(OPSERVO|INFRAPILOT)_[A-Z0-9_]+=' "${CONFIG_FILE}" 2>/dev/null || true)
  # Recorded identity lets the agent detect AMI/template clones at startup.
  local identity extra
  identity="$(instance_identity)"
  extra=""
  [ -n "${identity}" ] && extra="OPSERVO_MACHINE_ID=${identity}"
  # A multi-use fleet key (fleet_…) is persisted so a CLONE of this box can
  # re-register itself as a new server. Single-use ipk_ tokens are spent at
  # registration and must not linger in the config.
  case "${ENROLLMENT_TOKEN}" in
    fleet_*) extra="${extra}
OPSERVO_ENROLL_KEY=${ENROLLMENT_TOKEN}" ;;
  esac
  # The secret key lives here, so the file is root-only (0600).
  write_file "${CONFIG_FILE}" 0600 <<EOF
# Opservo agent configuration — managed by the installer.
# Contains a secret key; keep this file readable only by root.
OPSERVO_API_URL=${API_URL}
OPSERVO_AGENT_ID=${AGENT_ID}
OPSERVO_SECRET_KEY=${SECRET_KEY}
OPSERVO_BUFFER_PATH=${BUFFER_PATH}
# Opt-in: run dashboard-assigned private-network TCP uptime checks from this
# server (e.g. probe an internal RDS endpoint). Set to true, then:
#   systemctl restart infrapilot-agent
OPSERVO_ENABLE_PROBES=${probes}
# Opt-in: allow live terminal sessions opened from the dashboard (owners and
# admins, identity check every time, recorded). The server's switch in the
# dashboard must be on too. Set to true, then:
#   systemctl restart infrapilot-agent
OPSERVO_ENABLE_SHELL=${shell_opt}
${extra}${preserved}
EOF
  success "Wrote ${CONFIG_FILE}"
  if [ -n "${preserved_keys}" ]; then
    info "Preserved from existing config: ${preserved_keys}"
  fi
}

# ── Step 4: systemd unit ──────────────────────────────────────────────────────
write_unit() {
  write_file "${UNIT_FILE}" 0644 <<EOF
[Unit]
Description=Opservo Agent
Documentation=https://getopservo.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${CONFIG_FILE}
ExecStart=${INSTALL_PATH}
# Always restart (even on a clean exit) so the agent reliably returns after a
# reboot or a self-update re-exec.
Restart=always
RestartSec=5
# Persistent local buffer for the 24h offline store.
StateDirectory=infrapilot
# Hardening that does not interfere with collection OR with the opt-in remote
# actions (dispatched fixes run as children of this unit, so anything that
# would block sysctl/modprobe/cgroup/mount changes or hide /tmp is left off
# on purpose — see docs/agent-hardening.md).
NoNewPrivileges=true
ProtectHostname=true
RestrictRealtime=true
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
  success "Installed systemd unit ${UNIT_FILE}"
}

# ── Step 4b: GPU metrics dependency (Intel integrated only) ───────────────────
# Opservo reads NVIDIA (nvidia-smi) and AMD/newer-Intel (sysfs) GPU load with
# no extra packages. Intel integrated graphics (i915) expose no sysfs busy %, so
# they need intel_gpu_top from intel-gpu-tools. Install it best-effort when an
# Intel GPU is present and the tool is missing; never fail the install over it.
has_intel_gpu() {
  local v
  for v in /sys/class/drm/card*/device/vendor; do
    [ -r "${v}" ] || continue
    grep -qi '0x8086' "${v}" 2>/dev/null && return 0
  done
  return 1
}
ensure_gpu_tools() {
  command -v intel_gpu_top >/dev/null 2>&1 && return 0
  # Installing a package is a side effect some operators do not want from an
  # agent installer: OPSERVO_INSTALL_GPU_TOOLS=0 skips it (GPU load reads "—").
  [ "${OPSERVO_INSTALL_GPU_TOOLS:-1}" = "0" ] && return 0
  has_intel_gpu || return 0
  info "Intel GPU detected — installing intel-gpu-tools for GPU metrics (best effort)…"
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get install -y intel-gpu-tools >/dev/null 2>&1 || warn "Could not install intel-gpu-tools — GPU load will read as “—” on this server."
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y igt-gpu-tools >/dev/null 2>&1 || warn "Could not install igt-gpu-tools."
  elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -S --noconfirm intel-gpu-tools >/dev/null 2>&1 || warn "Could not install intel-gpu-tools."
  else
    warn "No supported package manager for intel-gpu-tools — GPU load will read as “—”."
  fi
}

# ── Step 5: start the agent ───────────────────────────────────────────────────
start_agent() {
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable infrapilot-agent.service >/dev/null 2>&1 || true
  $SUDO systemctl restart infrapilot-agent.service

  # Give it a moment, then confirm it is actually running.
  local i
  for i in 1 2 3 4 5; do
    if $SUDO systemctl is-active --quiet infrapilot-agent.service; then
      success "Agent is running and enabled on boot."
      return
    fi
    sleep 1
  done
  warn "The agent did not report active yet. Check: journalctl -u infrapilot-agent -n 50"
}

# ── Step 6: summary ───────────────────────────────────────────────────────────
print_summary() {
  printf '\n%s%sOpservo agent installed.%s\n' "${C_GREEN}" "${C_BOLD}" "${C_RESET}"
  printf '  Agent ID:  %s%s%s\n' "${C_BOLD}" "${AGENT_ID}" "${C_RESET}"
  printf '  Dashboard: %s%s/servers/%s%s\n' "${C_BOLD}" "${DASHBOARD_URL%/}" "${AGENT_ID}" "${C_RESET}"
  printf '\nManage the agent with:\n'
  printf '  systemctl status infrapilot-agent\n'
  printf '  journalctl -u infrapilot-agent -f\n'
  printf '\nOptional: to monitor MySQL, create a read-only user and put its login in\n'
  printf '  %s/mysql.cnf  (a [client] option file). The agent reads only that file.\n\n' "${CONFIG_DIR}"
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
uninstall() {
  printf '%s%sRemoving Opservo agent%s\n\n' "${C_BLUE}" "${C_BOLD}" "${C_RESET}"
  if [ -d /run/systemd/system ]; then
    $SUDO systemctl stop infrapilot-agent.service 2>/dev/null || true
    $SUDO systemctl disable infrapilot-agent.service 2>/dev/null || true
    $SUDO rm -f "${UNIT_FILE}"
    $SUDO systemctl daemon-reload 2>/dev/null || true
  fi
  $SUDO rm -f "${INSTALL_PATH}"
  $SUDO rm -rf "${CONFIG_DIR}"
  $SUDO rm -rf "${STATE_DIR}"
  success "Opservo agent removed from this server."
}

# ── Arguments ─────────────────────────────────────────────────────────────────
# Everything is env-driven so the one-liner stays `… | sudo env … bash`; the
# few flags exist for what an env var can't do well.
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --prompt)    PROMPT_TOKEN=1 ;;
      --uninstall) UNINSTALL=1 ;;
      --force)     FORCE=1 ;;
      -h|--help)
        sed -n '2,40p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'
        exit 0
        ;;
      *) fail "Unknown option: $1 (use --prompt, --force, --uninstall)" ;;
    esac
    shift
  done
}

# prompt_for_token reads the enrollment token from the terminal with echo off,
# so it never appears on a command line, in shell history, or in `ps`. The
# script itself arrives on stdin (`curl … | bash`), so the terminal is opened
# directly as /dev/tty; without one (CI, a pasted heredoc) the user is told to
# use the OPSERVO_TOKEN form instead of silently hanging or registering tokenless.
prompt_for_token() {
  if [ -n "${ENROLLMENT_TOKEN}" ]; then
    info "An enrollment token was supplied in the environment; --prompt ignored."
    return
  fi
  # /dev/tty exists even with no controlling terminal; opening it is the test.
  if ! { : </dev/tty; } 2>/dev/null; then
    fail "--prompt needs an interactive terminal. Without one, pass the token as OPSERVO_TOKEN=<token> instead."
  fi
  local token=""
  printf 'Paste the enrollment token from Add Server (it is not shown as you type): ' >/dev/tty
  IFS= read -rs token </dev/tty || true
  printf '\n' >/dev/tty
  token="${token//[[:space:]]/}"
  [ -n "${token}" ] || fail "No token entered."
  case "${token}" in
    ipk_*|fleet_*) : ;;
    *) warn "That does not look like an Opservo enrollment token (expected ipk_… or fleet_…); trying it anyway." ;;
  esac
  ENROLLMENT_TOKEN="${token}"
  success "Token received."
}

main() {
  parse_args "$@"
  if [ "${UNINSTALL}" = "1" ]; then
    uninstall
    return
  fi
  printf '%s%sOpservo agent installer%s\n\n' "${C_BLUE}" "${C_BOLD}" "${C_RESET}"
  if [ "${PROMPT_TOKEN}" = "1" ]; then
    prompt_for_token
  fi
  detect_platform
  download_binary
  resolve_credentials
  write_config
  ensure_gpu_tools
  write_unit
  start_agent
  print_summary
}

main "$@"
