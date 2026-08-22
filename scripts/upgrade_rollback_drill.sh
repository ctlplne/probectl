#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# Real v0.5.0 -> current -> v0.5.0 -> current lifecycle rehearsal against one
# disposable PostgreSQL database. It builds the historical binary from the
# signed repository tag, serves HTTPS at every stage, and checks a two-tenant
# data/key/audit fingerprint plus forced-RLS visibility after every transition.
set -euo pipefail

cd "$(dirname "$0")/.."

SOURCE_REF="${PROBECTL_UPGRADE_SOURCE_REF:-v0.5.0}"
DATABASE_URL="${PROBECTL_DATABASE_URL:-postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable}"
RESULT_FILE="${PROBECTL_UPGRADE_RESULT_FILE:-}"

# A drill with an "isolated" Compose project must not still share one fixed host
# listener. Keep the explicit override for controlled labs, otherwise scan a
# bounded high-port window using Bash's built-in /dev/tcp support. The control
# process remains loopback-only and the later HTTPS probe is the real oracle.
select_probe_port() {
  local start candidate offset
  start=$((20000 + ($$ % 30000)))
  for offset in $(seq 0 127); do
    candidate=$((20000 + ((start - 20000 + offset) % 40000)))
    if ! (exec 3<>"/dev/tcp/127.0.0.1/${candidate}") 2>/dev/null; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

PORT="${PROBECTL_UPGRADE_PROBE_PORT:-}"
if [ -z "$PORT" ]; then
  PORT="$(select_probe_port)" || {
    echo "upgrade drill: no free loopback probe port found in the bounded scan" >&2
    exit 69
  }
fi
case "$PORT" in
  *[!0-9]* | "") echo "upgrade drill: invalid probe port: $PORT" >&2; exit 64 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "upgrade drill: probe port is outside 1..65535: $PORT" >&2
  exit 64
fi
RUN_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
CURRENT_SHA="$(git rev-parse HEAD)"
SOURCE_SHA="$(git rev-parse "${SOURCE_REF}^{commit}")"
CURRENT_VERSION="$(tr -d '[:space:]' < VERSION)"
WORKTREE_STATE="clean"
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  WORKTREE_STATE="dirty"
  if [ "${PROBECTL_UPGRADE_ALLOW_DIRTY:-}" != "1" ]; then
    echo "upgrade drill: working tree is dirty; commit the target or set PROBECTL_UPGRADE_ALLOW_DIRTY=1 for a non-release rehearsal" >&2
    exit 66
  fi
fi
DRILL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/probectl-upgrade-rollback.XXXXXX")"
DRILL_DIR="$(cd "$DRILL_DIR" && pwd -P)"
SERVER_PID=""

case "$DRILL_DIR" in
  /tmp/probectl-upgrade-rollback.* | /private/tmp/probectl-upgrade-rollback.* | /var/folders/*/T/probectl-upgrade-rollback.* | /private/var/folders/*/T/probectl-upgrade-rollback.*) ;;
  *) echo "upgrade drill: refusing unsafe temporary path: $DRILL_DIR" >&2; exit 65 ;;
esac

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill -TERM "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$DRILL_DIR"
}
trap cleanup EXIT HUP INT TERM

step() { printf '\n== upgrade/rollback drill: %s ==\n' "$1"; }

mkdir "$DRILL_DIR/source" "$DRILL_DIR/certs"
git archive --format=tar "$SOURCE_REF" | tar -x -C "$DRILL_DIR/source"

step "build exact historical and current binaries"
(cd "$DRILL_DIR/source" && GOCACHE=/private/tmp/probectl-gocache go build -trimpath \
  -ldflags "-X github.com/imfeelingtheagi/probectl/internal/version.Version=0.5.0 -X github.com/imfeelingtheagi/probectl/internal/version.Commit=${SOURCE_SHA} -X github.com/imfeelingtheagi/probectl/internal/version.Date=${RUN_AT}" \
  -o "$DRILL_DIR/probectl-control-old" ./cmd/probectl-control)
GOCACHE=/private/tmp/probectl-gocache go build -trimpath \
  -ldflags "-X github.com/ctlplne/probectl/internal/version.Version=${CURRENT_VERSION} -X github.com/ctlplne/probectl/internal/version.Commit=${CURRENT_SHA} -X github.com/ctlplne/probectl/internal/version.Date=${RUN_AT}" \
  -o "$DRILL_DIR/probectl-control-current" ./cmd/probectl-control
GOCACHE=/private/tmp/probectl-gocache go build -trimpath \
  -o "$DRILL_DIR/probectl-upgrade-fixture" ./test/drill/upgradefixture
"$DRILL_DIR/probectl-control-old" version
"$DRILL_DIR/probectl-control-current" version
"$DRILL_DIR/probectl-control-current" gen-cert "$DRILL_DIR/certs" >/dev/null

export PROBECTL_DATABASE_URL="$DATABASE_URL"
export PROBECTL_ENVELOPE_KEY="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
export PROBECTL_SESSION_HMAC_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
export PROBECTL_TLS_CERT_FILE="$DRILL_DIR/certs/tls.crt"
export PROBECTL_TLS_KEY_FILE="$DRILL_DIR/certs/tls.key"
export PROBECTL_HTTP_ADDR="127.0.0.1:${PORT}"
export PROBECTL_AUTH_MODE="session"
export PROBECTL_MIGRATE_ON_BOOT="false"
# The fixture deliberately has two tenants. Keep the current binary's
# defense-in-depth posture explicit even though this local drill uses in-memory
# telemetry stores; otherwise current correctly refuses a multi-tenant DB under
# the single-tenant defaults.
export PROBECTL_FLOWSTORE_TENANT_SCOPING="true"
export PROBECTL_OTELSTORE_TENANT_SCOPING="true"
export PROBECTL_EBPFSTORE_TENANT_SCOPING="true"
export PROBECTL_PATHSTORE_TENANT_SCOPING="true"
export PROBECTL_ENDPOINTSTORE_TENANT_SCOPING="true"
export PROBECTL_INGEST_STRICT_TENANT_LANES="true"

serve_and_probe() {
  binary="$1"
  label="$2"
  log="$DRILL_DIR/${label}.log"
  "$binary" serve >"$log" 2>&1 &
  SERVER_PID=$!
  ready=""
  for _ in $(seq 1 80); do
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      echo "upgrade drill: ${label} exited before readiness" >&2
      sed -n '1,160p' "$log" >&2
      return 1
    fi
    if curl --silent --show-error --fail --cacert "$DRILL_DIR/certs/ca.crt" \
      "https://127.0.0.1:${PORT}/readyz" >"$DRILL_DIR/${label}-ready.json" 2>/dev/null; then
      ready="yes"
      break
    fi
    sleep 0.25
  done
  if [ "$ready" != "yes" ]; then
    echo "upgrade drill: ${label} did not become HTTPS-ready" >&2
    sed -n '1,160p' "$log" >&2
    return 1
  fi
  kill -TERM "$SERVER_PID"
  wait "$SERVER_PID"
  SERVER_PID=""
  echo "${label}: HTTPS ready, graceful stop passed"
}

step "install v0.5.0 schema and plant two-tenant sentinels"
"$DRILL_DIR/probectl-control-old" migrate
seed_line="$("$DRILL_DIR/probectl-upgrade-fixture" -mode seed)"
echo "$seed_line"
fixture_digest="$(printf '%s\n' "$seed_line" | sed -n 's/.* digest=\([0-9a-f]\{64\}\).*/\1/p')"
if [ -z "$fixture_digest" ]; then
  echo "upgrade drill: could not parse seed digest" >&2
  exit 1
fi
serve_and_probe "$DRILL_DIR/probectl-control-old" "source-v0.5.0"

step "inject a refused migration connection before the irreversible boundary"
if PROBECTL_DATABASE_URL="postgres://probectl:probectl@127.0.0.1:1/probectl?sslmode=disable&connect_timeout=1" \
  "$DRILL_DIR/probectl-control-current" migrate >"$DRILL_DIR/refused-migration.log" 2>&1; then
  echo "upgrade drill: intentionally unreachable migration unexpectedly succeeded" >&2
  exit 1
fi
"$DRILL_DIR/probectl-upgrade-fixture" -mode verify -expected "$fixture_digest"

step "upgrade to current migrations and binary"
"$DRILL_DIR/probectl-control-current" migrate
"$DRILL_DIR/probectl-upgrade-fixture" -mode verify -expected "$fixture_digest"
serve_and_probe "$DRILL_DIR/probectl-control-current" "target-current"

step "roll back the binary to v0.5.0 on the additive current schema"
"$DRILL_DIR/probectl-control-old" migrate
"$DRILL_DIR/probectl-upgrade-fixture" -mode verify -expected "$fixture_digest"
serve_and_probe "$DRILL_DIR/probectl-control-old" "rollback-v0.5.0"

step "roll forward again after rollback"
"$DRILL_DIR/probectl-control-current" migrate
"$DRILL_DIR/probectl-upgrade-fixture" -mode verify -expected "$fixture_digest"
serve_and_probe "$DRILL_DIR/probectl-control-current" "rollforward-current"

END_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ -n "$RESULT_FILE" ]; then
  mkdir -p "$(dirname "$RESULT_FILE")"
  if [ ! -s "$RESULT_FILE" ]; then
    echo "run_at,end_at,source_ref,source_sha,target_version,target_sha,fixture_sha256,upgrade,rollback,rollforward,tls,tenant_rls,key_hash,audit_continuity" >"$RESULT_FILE"
  fi
  printf '%s,%s,%s,%s,%s,%s,%s,pass,pass,pass,pass,pass,pass,pass\n' \
    "$RUN_AT" "$END_AT" "$SOURCE_REF" "$SOURCE_SHA" "$CURRENT_VERSION" "$CURRENT_SHA" "$fixture_digest" >>"$RESULT_FILE"
fi

echo
echo "upgrade/rollback drill: PASS — ${SOURCE_REF}@${SOURCE_SHA} -> ${CURRENT_VERSION}@${CURRENT_SHA} -> ${SOURCE_REF} -> ${CURRENT_VERSION}; HTTPS, fixture hash, tenant RLS, wrapped-key bytes, and audit continuity preserved"
echo "UPGRADE_RESULT run_at=${RUN_AT} end_at=${END_AT} source_ref=${SOURCE_REF} source_sha=${SOURCE_SHA} target_version=${CURRENT_VERSION} target_sha=${CURRENT_SHA} worktree=${WORKTREE_STATE} fixture_sha256=${fixture_digest} upgrade=pass rollback=pass rollforward=pass tls=pass tenant_rls=pass key_hash=pass audit_continuity=pass"
