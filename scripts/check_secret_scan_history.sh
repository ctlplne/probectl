#!/usr/bin/env bash
# Full-history secret scan gate.
#
# The old CI command scanned only HEAD with `--no-git`. That catches secrets in
# today's files, but not a credential committed yesterday and deleted today. This
# wrapper makes the invariant explicit: every reachable commit is scanned.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
GITLEAKS="${PROBECTL_GITLEAKS_BIN:-gitleaks}"
CONFIG="${PROBECTL_GITLEAKS_CONFIG:-$ROOT/.gitleaks.toml}"
LOG_OPTS="${PROBECTL_GITLEAKS_LOG_OPTS:---all}"
REPORT="${PROBECTL_GITLEAKS_REPORT:-${RUNNER_TEMP:-/tmp}/probectl-gitleaks-history.json}"

run_scan() {
  local repo="$1"
  local report="$2"

  mkdir -p "$(dirname "$report")"
  rm -f "$report"
  "$GITLEAKS" git \
    --redact=100 \
    --no-banner \
    --config "$CONFIG" \
    --log-opts "$LOG_OPTS" \
    --report-format json \
    --report-path "$report" \
    "$repo"
}

planted_history_selftest() {
  local tmp repo report
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/probectl-secret-scan.XXXXXX")"
  PROBECTL_SECRET_SCAN_SELFTEST_TMP="$tmp"
  repo="$tmp/repo"
  report="$tmp/report.json"
  trap 'rm -rf "$PROBECTL_SECRET_SCAN_SELFTEST_TMP"' EXIT

  git init -q "$repo"
  git -C "$repo" config user.name "probectl secret scan"
  git -C "$repo" config user.email "security@probectl.local"

  mkdir -p "$repo/planted"
  printf '%s\n' \
    "-----BEGIN RSA PRIVATE KEY-----" \
    "MIIEpAIBAAKCAQEA7fakeHistoricalSecretDetectorProbeOnly" \
    "-----END RSA PRIVATE KEY-----" > "$repo/planted/history_secret.pem"
  git -C "$repo" add planted/history_secret.pem
  git -C "$repo" commit -q -m "test: plant historical secret"
  git -C "$repo" rm -q planted/history_secret.pem
  git -C "$repo" commit -q -m "test: remove historical secret"

  if run_scan "$repo" "$report"; then
    echo "secret-scan self-test failed: planted deleted private key passed the full-history gate" >&2
    exit 1
  fi

  if [[ ! -s "$report" ]]; then
    echo "secret-scan self-test failed: gitleaks rejected the planted repo without writing a report" >&2
    exit 1
  fi

  echo "secret-scan self-test passed: planted deleted private key fails the full-history gate"
}

case "${PROBECTL_SECRET_SCAN_SELFTEST:-}" in
  "")
    ;;
  planted)
    planted_history_selftest
    exit 0
    ;;
  *)
    echo "unknown PROBECTL_SECRET_SCAN_SELFTEST=${PROBECTL_SECRET_SCAN_SELFTEST}" >&2
    exit 2
    ;;
esac

echo "secret-scan: scanning all git history with ${GITLEAKS} (${LOG_OPTS}); report: ${REPORT}"
run_scan "$ROOT" "$REPORT"
