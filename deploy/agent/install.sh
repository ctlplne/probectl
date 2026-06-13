#!/usr/bin/env bash
#
# install.sh — VM/bare-metal installer for the probectl eBPF agent (U-016).
#
#   sudo ./install.sh [--verify] <path-to-probectl-ebpf-agent-binary> [config.yaml]
#
# --verify (SUPPLY-002): before installing, cryptographically verify the binary
# against its cosign keyless signature. Looks for <binary>.sig + <binary>.pem
# (or set PROBECTL_COSIGN_SIG / PROBECTL_COSIGN_CERT) and runs `cosign
# verify-blob` pinned to the probectl release-workflow identity. Requires cosign
# on PATH; FAILS CLOSED if cosign is missing, the sig/cert are absent, or
# verification fails — an unsigned/tampered binary is never installed.
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

[ "$(id -u)" -eq 0 ] || { echo "install.sh: run as root (sudo)" >&2; exit 1; }

# SUPPLY-002: optional --verify (or PROBECTL_VERIFY_COSIGN=1) gates install on a
# cosign signature check. Repo identity is the probectl release workflow on a
# tag — the same identity release.yml signs with.
VERIFY=0
[ "${PROBECTL_VERIFY_COSIGN:-0}" = "1" ] && VERIFY=1
if [ "${1:-}" = "--verify" ]; then VERIFY=1; shift; fi
COSIGN_ISSUER="${PROBECTL_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
COSIGN_IDENTITY_REGEXP="${PROBECTL_COSIGN_IDENTITY_REGEXP:-^https://github.com/[^/]+/probectl/\.github/workflows/release\.yml@refs/tags/}"

BIN="${1:?usage: install.sh [--verify] <path-to-probectl-ebpf-agent-binary> [config.yaml]}"
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
  # SUPPLY-003: installing + enabling a privileged (CAP_BPF) binary with no
  # signature check. Not fatal (air-gap operators may verify out-of-band), but
  # print a loud, unmissable reminder so an unverified install is a conscious
  # choice, not an accident.
  echo "install.sh: WARNING — installing ${BIN} WITHOUT signature verification." >&2
  echo "install.sh:   This binary is granted CAP_BPF/CAP_PERFMON. Verify it first:" >&2
  echo "install.sh:     re-run with --verify (needs <binary>.sig + <binary>.pem), or" >&2
  echo "install.sh:     follow docs/verify-artifacts.md to cosign-verify before installing." >&2
fi
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
echo "unit     : ${UNIT} (enabled; CAP_BPF+CAP_PERFMON — edit the unit per deploy/agent/README.md for kernels < 5.8)"
echo "config   : /etc/probectl/ebpf-agent.yaml"
echo "start    : systemctl start ${UNIT} && journalctl -fu ${UNIT}"
