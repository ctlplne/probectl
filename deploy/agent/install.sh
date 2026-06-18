#!/usr/bin/env bash
#
# install.sh — VM/bare-metal installer for the probectl eBPF agent (U-016).
#
#   sudo ./install.sh <path-to-probectl-ebpf-agent-binary> [config.yaml]
#
# Verification is ON by default (SUPPLY-002): before installing, verify the binary
# against its cosign keyless signature. Looks for <binary>.sig + <binary>.pem
# (or set PROBECTL_COSIGN_SIG / PROBECTL_COSIGN_CERT) and runs `cosign
# verify-blob` pinned to the probectl release-workflow identity. Requires cosign
# on PATH; FAILS CLOSED if cosign is missing, the sig/cert are absent, or
# verification fails — an unsigned/tampered binary is never installed.
# Break-glass for an already-verified air-gap artifact requires BOTH --no-verify
# and PROBECTL_UNVERIFIED_INSTALL_ACK=allow-unsigned-cap-bpf-code.
#
# Installs the binary, the dedicated non-root system user, the hardened
# systemd unit (deploy/agent/probectl-ebpf-agent.service — ambient
# CAP_BPF+CAP_PERFMON, syscall filter, namespace lockdown; U-052), and a
# config. Air-gap friendly: takes a LOCAL binary, downloads nothing, never
# self-updates (updates are an operator action: rerun with a new binary).
# Idempotent — safe to rerun; an existing config is never overwritten.
set -euo pipefail

UNIT=probectl-ebpf-agent.service
HERE="$(cd "$(dirname "$0")" && pwd)"

# SUPPLY-002: verification is the default for this privileged installer. Repo
# identity is the probectl release workflow on a tag — the same identity
# release.yml signs with. The legacy PROBECTL_VERIFY_COSIGN=0 env and the
# --no-verify flag are break-glass only and require the acknowledgement below.
VERIFY="${PROBECTL_VERIFY_COSIGN:-1}"
case "${VERIFY}" in
  1|true|TRUE|yes|YES) VERIFY=1 ;;
  0|false|FALSE|no|NO) VERIFY=0 ;;
  *) echo "install.sh: PROBECTL_VERIFY_COSIGN must be true/false" >&2; exit 1 ;;
esac
while [ "${1:-}" = "--verify" ] || [ "${1:-}" = "--no-verify" ]; do
  case "$1" in
    --verify) VERIFY=1 ;;
    --no-verify) VERIFY=0 ;;
  esac
  shift
done
COSIGN_ISSUER="${PROBECTL_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
COSIGN_IDENTITY_REGEXP="${PROBECTL_COSIGN_IDENTITY_REGEXP:-^https://github.com/[^/]+/probectl/\.github/workflows/release\.yml@refs/tags/}"
UNVERIFIED_ACK_VALUE="allow-unsigned-cap-bpf-code"

BIN="${1:?usage: install.sh [--verify|--no-verify] <path-to-probectl-ebpf-agent-binary> [config.yaml]}"
[ -f "${BIN}" ] || { echo "install.sh: no binary at ${BIN}" >&2; exit 1; }

if [ "${VERIFY}" = "1" ]; then
  command -v cosign >/dev/null 2>&1 || {
    echo "install.sh: --verify requires cosign on PATH (https://docs.sigstore.dev) — refusing to install unverified (SUPPLY-002)" >&2
    exit 1
  }
  SIG="${PROBECTL_COSIGN_SIG:-${BIN}.sig}"
  CERT="${PROBECTL_COSIGN_CERT:-${BIN}.pem}"
  [ -f "${SIG}" ]  || { echo "install.sh: --verify: signature not found at ${SIG} (set PROBECTL_COSIGN_SIG)" >&2; exit 1; }
  [ -f "${CERT}" ] || { echo "install.sh: --verify: certificate not found at ${CERT} (set PROBECTL_COSIGN_CERT)" >&2; exit 1; }
  echo "install.sh: verifying ${BIN} with cosign (identity ${COSIGN_IDENTITY_REGEXP})..."
  cosign verify-blob \
    --certificate "${CERT}" \
    --signature "${SIG}" \
    --certificate-oidc-issuer "${COSIGN_ISSUER}" \
    --certificate-identity-regexp "${COSIGN_IDENTITY_REGEXP}" \
    "${BIN}" || {
      echo "install.sh: COSIGN VERIFICATION FAILED for ${BIN} — refusing to install (SUPPLY-002, fail closed)" >&2
      exit 1
    }
  echo "install.sh: cosign verification OK"
else
  if [ "${PROBECTL_UNVERIFIED_INSTALL_ACK:-}" != "${UNVERIFIED_ACK_VALUE}" ]; then
    echo "install.sh: refusing unverified privileged install (SUPPLY-002)." >&2
    echo "install.sh: verification is default; provide <binary>.sig + <binary>.pem, or for break-glass set:" >&2
    echo "install.sh:   PROBECTL_UNVERIFIED_INSTALL_ACK=${UNVERIFIED_ACK_VALUE} ./install.sh --no-verify ..." >&2
    exit 1
  fi
  echo "install.sh: BREAK-GLASS — installing ${BIN} WITHOUT signature verification." >&2
  echo "install.sh:   This binary is granted CAP_BPF/CAP_PERFMON; record the out-of-band verification evidence." >&2
fi

[ "$(id -u)" -eq 0 ] || { echo "install.sh: run as root (sudo)" >&2; exit 1; }
[ -f "${HERE}/${UNIT}" ] || { echo "install.sh: ${UNIT} not next to this script" >&2; exit 1; }

# Preflight: the kernel matrix (deploy/agent/README.md).
KVER="$(uname -r)"
if [ ! -r /sys/kernel/btf/vmlinux ]; then
  echo "install.sh: WARNING — /sys/kernel/btf/vmlinux missing (kernel ${KVER}):" >&2
  echo "  the CO-RE loader needs a BTF kernel (>= 5.8 on mainstream distros)." >&2
fi

# Dedicated non-root system user (the unit runs with ambient caps, no root).
if ! id -u probectl-agent >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin probectl-agent
  echo "created system user probectl-agent"
fi

install -m 0755 "${BIN}" /usr/local/bin/probectl-ebpf-agent
install -d -m 0755 /etc/probectl
install -d -m 0750 -o probectl-agent -g probectl-agent /var/lib/probectl

# Config: install the given file, or a fail-closed sample on first install.
if [ -n "${2:-}" ]; then
  install -m 0640 -g probectl-agent "$2" /etc/probectl/ebpf-agent.yaml
elif [ ! -f /etc/probectl/ebpf-agent.yaml ]; then
  cat > /etc/probectl/ebpf-agent.yaml <<'EOF'
# probectl eBPF agent — minimal config (docs/ebpf-agent.md, docs/configuration.md).
# The agent refuses to start until tenant_id and the bus are set, and refuses
# plaintext kafka without the explicit dev-only override (U-010).
tenant_id: ""           # REQUIRED: the tenant these flows belong to
bus:
  mode: kafka
  brokers: []           # e.g. ["kafka.internal:9093"]
# Bus TLS via env in the unit: PROBECTL_EBPF_BUS_TLS_ENABLED=true,
# PROBECTL_EBPF_BUS_TLS_CA_FILE=/etc/probectl/bus-ca.crt
EOF
  chgrp probectl-agent /etc/probectl/ebpf-agent.yaml
  chmod 0640 /etc/probectl/ebpf-agent.yaml
  echo "wrote sample /etc/probectl/ebpf-agent.yaml — set tenant_id + brokers before starting"
fi

install -m 0644 "${HERE}/${UNIT}" /etc/systemd/system/${UNIT}
systemctl daemon-reload
systemctl enable ${UNIT} >/dev/null

echo
echo "installed: /usr/local/bin/probectl-ebpf-agent ($(/usr/local/bin/probectl-ebpf-agent version 2>/dev/null || echo unknown))"
echo "unit     : ${UNIT} (enabled; CAP_BPF+CAP_PERFMON — SYS_ADMIN requires the explicit legacy exception in deploy/agent/README.md)"
echo "config   : /etc/probectl/ebpf-agent.yaml"
echo "start    : systemctl start ${UNIT} && journalctl -fu ${UNIT}"
