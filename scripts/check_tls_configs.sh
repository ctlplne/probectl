#!/usr/bin/env bash
#
# unified-TLS gate (Sprint 12 — WIRE-005/WIRE-007): every probectl listener and
# probectl↔probectl client takes its TLS policy from internal/crypto (the ONE
# hardened config; TLS 1.3 floor server-side). A bespoke `tls.Config{...}`
# literal outside internal/crypto is how a weak receiver config sneaks back in
# (the original WIRE-005: OTLP/MCP had default cipher suites) — this gate
# fails the build on any new one.
#
# Deliberate allowlist (OUTBOUND probe/integration clients speaking to
# THIRD-PARTY endpoints, where a 1.3-only floor would break legitimate
# monitoring targets; each keeps cert validation on and a 1.2 floor):
#   internal/canary/http.go   — operator-monitored HTTPS targets
#   internal/canary/dns.go    — DoT/DoH resolvers
set -euo pipefail

cd "$(dirname "$0")/.."

allow='^internal/crypto/|^internal/canary/http\.go|^internal/canary/dns\.go'

violations="$(grep -rn 'tls\.Config{' --include='*.go' internal/ cmd/ ee/ 2>/dev/null \
  | grep -v '_test\.go:' \
  | grep -vE "^(${allow})" || true)"

if [ "${SELFTEST:-0}" = "1" ]; then
  probe='cmd/foo/main.go:10:	cfg := &tls.Config{MinVersion: tls.VersionTLS10}'
  echo "${probe}" | grep -q 'tls\.Config{' \
    || { echo "SELFTEST FAILED: pattern missed ${probe}" >&2; exit 1; }
fi

if [ -n "${violations}" ]; then
  echo "BESPOKE tls.Config literal outside internal/crypto (WIRE-005):" >&2
  echo "${violations}" >&2
  echo "" >&2
  echo "Use crypto.ServerTLSConfig / ServerMTLSConfig* / InternalClientTLSConfig / HardenedClientTLSConfig — the TLS policy lives in internal/crypto. Outbound third-party probe clients belong on this script's allowlist with a justification." >&2
  exit 1
fi

echo "unified-TLS gate: OK (no bespoke tls.Config outside internal/crypto + the probe-client allowlist)"
