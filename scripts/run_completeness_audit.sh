#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# CL-002 exact-SHA delivery audit. Phases are deliberately separable:
#   static   source-only checks (no Docker daemon)
#   prepare  clean-SHA images, short-lived PKI, runtime secrets
#   run      disposable real stack + CLI/browser/store evidence
#   seal     positive + negative signed receipts and semantic lint controls
#   verify   cryptographic verification; promotion only with out-of-band trust
#   cleanup  destroy one prepared state's stack and transient credentials
#   all      prepare, run, seal, verify
#   review-* governed non-runtime review phases delegated to review.sh

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
LIVE_COMPOSE_FILE="${REPO_ROOT}/deploy/compose/completeness-audit.yml"
AUDIT_AUTHORITY_REL="docs/quality/delivery-audit-review-protocols.json"
PHASE="${1:-all}"

TENANT_A="aaaaaaaa-0000-4000-8000-000000000001"
TENANT_B="bbbbbbbb-0000-4000-8000-000000000002"
USER_A="aaaaaaaa-0000-4000-8000-000000001001"
USER_B="bbbbbbbb-0000-4000-8000-000000001002"
ROLE_A="aaaaaaaa-0000-4000-8000-000000002001"
ROLE_B="bbbbbbbb-0000-4000-8000-000000002002"

log() { printf '[completeness-audit] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"; }

utc_now() {
  node -e 'process.stdout.write(new Date().toISOString())'
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

require_safe_path() {
  case "$1" in
    *$'\n'*|*$'\r'*|*"'"*) die "audit paths may not contain control characters or single quotes: $1" ;;
  esac
}

require_safe_id() {
  [[ "$2" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
    die "$1 must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
}

require_env_value() {
  case "$2" in
    *$'\n'*|*$'\r'*|*"'"*) die "$1 contains a value that cannot be persisted safely" ;;
  esac
}

static_checks() {
  need bash
  need go
  need node
  need rg
  need sed
  bash -n "${REPO_ROOT}/scripts/run_completeness_audit.sh"
  bash -n "${REPO_ROOT}/deploy/compose/completeness-audit/review.sh"
  node --check "${REPO_ROOT}/scripts/completeness_audit_browser.mjs"
  if rg -n '^[[:space:]]*ports:' "$LIVE_COMPOSE_FILE" >/dev/null; then
    die "audit Compose must not publish host ports"
  fi
  rg -q 'internal:[[:space:]]*true' "$LIVE_COMPOSE_FILE" || die "audit network is not internal"
  rg -q 'GO_TAGS=""' "${REPO_ROOT}/deploy/docker/Dockerfile" || die "release Dockerfile lost empty-tag default"
  rg -q 'ignoreHTTPSErrors:[[:space:]]*false' "${REPO_ROOT}/scripts/completeness_audit_browser.mjs" ||
    die "browser audit must explicitly keep TLS verification enabled"
  rg -q 'getByRole\("link", \{ name: "Log in with Email", exact: true \}\)' \
    "${REPO_ROOT}/scripts/completeness_audit_browser.mjs" ||
    die "browser audit must exercise Dex connector selection before the password form"
  rg -q 'const productPage = await context\.newPage\(\)' \
    "${REPO_ROOT}/scripts/completeness_audit_browser.mjs" ||
    die "browser audit must keep the polling landing document alive while opening each asserted product route"
  rg -Fq 'observeNetwork(productPage, requests, failures)' \
    "${REPO_ROOT}/scripts/completeness_audit_browser.mjs" ||
    die "browser audit must retain strict network/page-error observation on the context-shared product page"
  if rg -n 'page\.goto\(`\$\{baseURL\}\$\{spec\.product_path\}`' \
    "${REPO_ROOT}/scripts/completeness_audit_browser.mjs" >/dev/null; then
    die "browser audit must not hard-navigate the polling landing page and manufacture WebKit access-control errors"
  fi
  if rg -n 'page\.route|route\.fulfill|ignoreHTTPSErrors:[[:space:]]*true|NODE_TLS_REJECT_UNAUTHORIZED|--insecure|-k([[:space:]]|$)' \
    "${REPO_ROOT}/scripts/completeness_audit_browser.mjs" "$LIVE_COMPOSE_FILE" >/dev/null; then
    die "fixture/interception/TLS-bypass marker found in the real audit layer"
  fi
  local plaintext_probe_count
  plaintext_probe_count="$(rg -o '^[[:space:]]+assert_plaintext_http_rejected (control|OTLP/HTTP|Dex|ClickHouse|Prometheus)' \
    "${REPO_ROOT}/scripts/run_completeness_audit.sh" | wc -l | tr -d ' ')"
  [[ "$plaintext_probe_count" == "5" ]] ||
    die "all five HTTP listeners need protocol-semantic plaintext rejection probes"
  rg -q '\[\[ "\$status" == "400" \]\]' "${REPO_ROOT}/scripts/run_completeness_audit.sh" ||
    die "plaintext HTTP probes must reject every application status and allow only the TLS-layer 400"
  rg -Fq 'https://dex:5556/dex/auth/local?req=invalid' "${REPO_ROOT}/scripts/run_completeness_audit.sh" ||
    die "Dex negative auth probe must target an invalid authorization continuation, not its intentionally public login entry point"
  rg -Fq 'https://clickhouse:8443/?query=SELECT%201' "${REPO_ROOT}/scripts/run_completeness_audit.sh" ||
    die "ClickHouse negative auth probe must target the protected SQL endpoint, not its intentionally public root liveness endpoint"
  rg -Fq '[[ "$clickhouse_auth" == "403" ]]' "${REPO_ROOT}/scripts/run_completeness_audit.sh" ||
    die "ClickHouse negative auth probe must require the pinned server's exact unauthenticated SQL status"
  if rg -n 'https?://[^/@[:space:]]+:[^/@[:space:]]+@' "$LIVE_COMPOSE_FILE" \
    "${REPO_ROOT}/deploy/compose/completeness-audit" >/dev/null; then
    die "URL userinfo is forbidden in the audit layer"
  fi
  if rg -n '^[[:space:]]+CLICKHOUSE_DB:' "$LIVE_COMPOSE_FILE" >/dev/null; then
    die "TLS-only ClickHouse must leave CLICKHOUSE_DB unset; the 24.8 entrypoint initializes it over forbidden plaintext port 9000"
  fi
  if rg -n 'KAFKA_SSL_(KEYSTORE|TRUSTSTORE)_(FILENAME|CREDENTIALS)|KAFKA_SSL_KEY_CREDENTIALS' "$LIVE_COMPOSE_FILE" >/dev/null; then
    die "Apache Kafka requires ssl.*.location/password properties; Confluent filename/credentials properties leave the broker without a usable TLS key"
  fi
  local kafka_tls_key
  for kafka_tls_key in KAFKA_SSL_KEYSTORE_LOCATION KAFKA_SSL_KEYSTORE_PASSWORD KAFKA_SSL_KEY_PASSWORD \
    KAFKA_SSL_TRUSTSTORE_LOCATION KAFKA_SSL_TRUSTSTORE_PASSWORD; do
    rg -q "^[[:space:]]+${kafka_tls_key}:" "$LIVE_COMPOSE_FILE" ||
      die "Kafka TLS configuration is missing ${kafka_tls_key}"
  done
  rg -q '^[[:space:]]+KAFKA_AUTO_CREATE_TOPICS_ENABLE:[[:space:]]+"false"' "$LIVE_COMPOSE_FILE" ||
    die "audit Kafka must disable implicit topic creation"
  local kafka_topics_init topic
  kafka_topics_init="$(sed -n '/^  kafka-topics-init:/,/^  clickhouse:/p' "$LIVE_COMPOSE_FILE")"
  for topic in probectl.otlp.metrics probectl.otlp.traces probectl.otlp.logs \
    probectl.deadletter.otlp.metrics probectl.deadletter.otlp.traces probectl.deadletter.otlp.logs; do
    [[ "$kafka_topics_init" == *"$topic"* ]] ||
      die "Kafka topic init is missing required OTLP lane topic ${topic}"
  done
  [[ "$kafka_topics_init" == *'--command-config /etc/kafka/secrets/client.properties'* ]] ||
    die "Kafka topic init must authenticate and verify TLS with client.properties"
  [[ "$kafka_topics_init" == *'--partitions 3 --replication-factor 1'* ]] ||
    die "Kafka topic init must use the deterministic three-partition single-broker audit shape"
  local control_compose
  control_compose="$(sed -n '/^  control:/,/^  cli:/p' "$LIVE_COMPOSE_FILE")"
  [[ "$control_compose" == *'kafka-topics-init: { condition: service_completed_successfully }'* ]] ||
    die "control must wait for the authenticated Kafka topic initialization gate"
  rg -q 'clickhouse/users\.xml:/etc/clickhouse-server/users\.d/audit-settings\.xml:ro' "$LIVE_COMPOSE_FILE" ||
    die "ClickHouse tenant setting profile is not mounted into users.d"
  rg -q "<SQL_probectl_tenant>''</SQL_probectl_tenant>" \
    "${REPO_ROOT}/deploy/compose/completeness-audit/clickhouse/users.xml" ||
    die "ClickHouse users profile does not define the fail-closed tenant setting"
  if rg -n "ALTER USER probectl SETTINGS SQL_probectl_tenant" "$LIVE_COMPOSE_FILE" >/dev/null; then
    die "users.xml-backed ClickHouse users are read-only to ALTER USER; validate the profile setting instead"
  fi
  rg -q 'promtool.*check.*healthy|"/bin/promtool"' "$LIVE_COMPOSE_FILE" ||
    die "Prometheus health must use its bundled TLS-verifying promtool client"
  rg -q 'health-client\.yml' "$LIVE_COMPOSE_FILE" ||
    die "Prometheus health is missing its owner-only authenticated TLS client config"
  if rg -n 'wget.*prometheus:9090' "$LIVE_COMPOSE_FILE" >/dev/null; then
    die "the pinned Prometheus BusyBox wget cannot validate certificates; use promtool"
  fi
  if rg -n 'local .*label="\$3".*output=.*\$\{label\}' "${REPO_ROOT}/scripts/run_completeness_audit.sh" >/dev/null; then
    die "shell locals must be initialized before a later local initializer expands them under nounset"
  fi
  if rg -n 'tmpfs:[[:space:]]*\[/tmp:[^]"]+,mode=' "$LIVE_COMPOSE_FILE" >/dev/null; then
    die "tmpfs short syntax containing a comma must be YAML-quoted as one mount"
  fi
  if rg -n -- '--entrypoint(=|[[:space:]]+)id([[:space:]]|$)' \
    "${REPO_ROOT}/scripts/run_completeness_audit.sh" >/dev/null; then
    die "runtime identity checks must not assume the distroless release image contains the id utility"
  fi
  rg -q 'store-probe[[:space:]]+identity' "${REPO_ROOT}/scripts/run_completeness_audit.sh" ||
    die "runtime inventory must invoke the distroless helper's effective-identity mode"
  rg -Fq 'effectiveIdentity{UID: os.Geteuid(), GID: os.Getegid()}' \
    "${REPO_ROOT}/deploy/compose/completeness-audit/probe/main.go" ||
    die "distroless store probe must expose its kernel-reported effective UID/GID"
  rg -Fq 'process.geteuid(),gid:process.getegid()' "${REPO_ROOT}/scripts/run_completeness_audit.sh" ||
    die "Node-based audit helpers must expose their kernel-reported effective UID/GID"
  rg -Fq 'length == 1 and .[0] == {uid:$uid,gid:$gid}' "${REPO_ROOT}/scripts/run_completeness_audit.sh" ||
    die "runtime identity evidence must be one exact UID/GID object"
  local tls_probe_compose
  tls_probe_compose="$(sed -n '/^  tls-probe:/,/^  browser:/p' "$LIVE_COMPOSE_FILE")"
  [[ "$tls_probe_compose" == *'${AUDIT_CERT_DIR:?AUDIT_CERT_DIR is required}/ca.crt:/audit/ca.crt:ro'* ]] ||
    die "TLS served-leaf probe must mount exactly the public CA file"
  if rg -q 'audit_pki|/audit/pki|AUDIT_PRIVATE_DIR|control_secrets|kafka_secrets|pgpass|tls\.key' <<<"$tls_probe_compose"; then
    die "TLS served-leaf probe must not mount private PKI or service credentials"
  fi
  gofmt_diff="$(cd "$REPO_ROOT" && gofmt -d deploy/compose/completeness-audit/probe/main.go deploy/compose/completeness-audit/probe/main_test.go)"
  [[ -z "$gofmt_diff" ]] || die "audit probe needs gofmt"
  local peer_capture_count peer_field_count
  peer_capture_count="$(rg -o 'capture_served_leaf_sha256 [a-z_]+ [a-z]+:[0-9]+ [a-z]+' \
    "${REPO_ROOT}/scripts/run_completeness_audit.sh" | wc -l | tr -d ' ')"
  peer_field_count="$(rg -o 'peer_certificate_sha256:\$[a-z_]+_peer' \
    "${REPO_ROOT}/scripts/run_completeness_audit.sh" | wc -l | tr -d ' ')"
  [[ "$peer_capture_count" == "7" && "$peer_field_count" == "7" ]] ||
    die "all seven TLS listeners need independent served-leaf capture and evidence fields"
  log "static audit checks passed"
}

case "$PHASE" in
  static|prepare|run|seal|verify|cleanup|all|review-prepare|review-seal|review-verify|review-cleanup|review-all) ;;
  *) die "usage: $0 [static|prepare|run|seal|verify|cleanup|all|review-prepare|review-seal|review-verify|review-cleanup|review-all]" ;;
esac

if [[ "$PHASE" == "static" ]]; then
  static_checks
  exit 0
fi

case "$PHASE" in
  review-*) exec bash "${REPO_ROOT}/deploy/compose/completeness-audit/review.sh" "${PHASE#review-}" ;;
esac

need git
need go
need jq
need openssl

GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
TREE_SHA="$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')"
SHA12="${GIT_SHA:0:12}"
COMMIT_DATE="$(git -C "$REPO_ROOT" show -s --format=%cI HEAD)"

if [[ "$PHASE" == "prepare" || "$PHASE" == "all" ]]; then
  if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal)" ]]; then
    die "VERIFIED delivery evidence requires a clean checkout"
  fi
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  STATE_DIR="${PROBECTL_AUDIT_STATE_DIR:-${REPO_ROOT}/../evidence/completeness/CL-002/${SHA12}-${timestamp}}"
  require_safe_path "$STATE_DIR"
  [[ ! -e "$STATE_DIR" ]] || die "refusing to reuse audit state: $STATE_DIR"
  mkdir -p "$STATE_DIR" "$STATE_DIR/artifacts" "$STATE_DIR/runtime" "$STATE_DIR/private" "$STATE_DIR/bin" "$STATE_DIR/drivers"
  chmod 0700 "$STATE_DIR" "$STATE_DIR/runtime" "$STATE_DIR/private" "$STATE_DIR/bin" "$STATE_DIR/drivers"
  chmod 0770 "$STATE_DIR/artifacts"
else
  STATE_DIR="${PROBECTL_AUDIT_STATE_DIR:?set PROBECTL_AUDIT_STATE_DIR for $PHASE}"
  [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || die "audit state must be a real directory: $STATE_DIR"
fi

STATE_DIR="$(CDPATH= cd -- "$STATE_DIR" && pwd -P)"
ARTIFACT_DIR="${STATE_DIR}/artifacts"
RUNTIME_DIR="${STATE_DIR}/runtime"
PRIVATE_DIR="${STATE_DIR}/private"
BIN_DIR="${STATE_DIR}/bin"
CERT_DIR="${STATE_DIR}/certs"
DRIVER_DIR="${STATE_DIR}/drivers"
ENV_FILE="${RUNTIME_DIR}/audit.env"
require_safe_path "$STATE_DIR"

STATE_KEYS=(
  AUDIT_COMPOSE_PROJECT AUDIT_CONTROL_IMAGE AUDIT_CLI_IMAGE AUDIT_BROWSER_IMAGE
  AUDIT_CERT_DIR AUDIT_RUNTIME_DIR AUDIT_ARTIFACT_DIR AUDIT_BIN_DIR AUDIT_PRIVATE_DIR AUDIT_SOURCE_DIR
  AUDIT_DRIVER_DIR AUDIT_BROWSER_SCRIPT AUDIT_BROWSER_DRIVER_PATH AUDIT_BROWSER_DRIVER_SHA256
  AUDIT_SOURCE_ARCHIVE AUDIT_SOURCE_ARCHIVE_SHA256 AUDIT_COMPOSE_FILE AUDIT_GIT_SHA
  AUDIT_TREE_SHA AUDIT_STARTED_AT AUDIT_TENANT_A AUDIT_TENANT_B AUDIT_TEST_A_NAME
  AUDIT_HOST_UID AUDIT_HOST_GID
  AUDIT_TEST_B_NAME AUDIT_ITEM AUDIT_CAPABILITY_ID AUDIT_CAPABILITY_DRIVER_PATH
  AUDIT_CAPABILITY_DRIVER_SOURCE_PATH AUDIT_CAPABILITY_DRIVER_SHA256 AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA
  AUDIT_BROWSER_DRIVER_SOURCE_PATH AUDIT_BROWSER_DRIVER_GIT_BLOB_SHA POSTGRES_PASSWORD KAFKA_STORE_PASSWORD
  KAFKA_SASL_PASSWORD CLICKHOUSE_USER CLICKHOUSE_PASSWORD PROMETHEUS_USER PROMETHEUS_PASSWORD DEX_CLIENT_SECRET
  DEX_AUDIT_PASSWORD DEX_AUDIT_PASSWORD_HASH PROBECTL_SESSION_HMAC_KEY
)

state_key_known() {
  local candidate="$1" allowed
  for allowed in "${STATE_KEYS[@]}"; do
    [[ "$candidate" == "$allowed" ]] && return 0
  done
  return 1
}

load_state() {
  if [[ -n "${PROBECTL_AUDIT_CAPABILITY_DRIVER+x}" || -n "${PROBECTL_AUDIT_BROWSER_DRIVER+x}" ]]; then
    die "resume refuses live driver overrides; prepare already froze all driver bytes"
  fi
  [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || die "missing prepared runtime env: $ENV_FILE"
  [[ "$(stat -f '%Lp' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE")" == "600" ]] ||
    die "prepared runtime env must be mode 0600"
  local key quoted value required seen=$'\n'
  for required in "${STATE_KEYS[@]}"; do unset "$required"; done
  while IFS='=' read -r key quoted; do
    [[ -n "$key" ]] || die "blank line in prepared runtime env"
    state_key_known "$key" || die "unexpected key in prepared runtime env: $key"
    case "$seen" in *$'\n'"$key"$'\n'*) die "duplicate key in prepared runtime env: $key" ;; esac
    seen+="${key}"$'\n'
    [[ "$quoted" == "'"*"'" && ${#quoted} -ge 2 ]] || die "malformed prepared runtime value for $key"
    value="${quoted#\'}"
    value="${value%\'}"
    require_env_value "$key" "$value"
    printf -v "$key" '%s' "$value"
    export "$key"
  done < "$ENV_FILE"
  for required in "${STATE_KEYS[@]}"; do
    case "$seen" in *$'\n'"$required"$'\n'*) ;; *) die "missing key in prepared runtime env: $required" ;; esac
  done
  [[ "$AUDIT_GIT_SHA" =~ ^[0-9a-f]{40}$ && "$AUDIT_TREE_SHA" =~ ^[0-9a-f]{40}$ ]] ||
    die "prepared source identity is malformed"
  require_safe_id AUDIT_ITEM "$AUDIT_ITEM"
  require_safe_id AUDIT_CAPABILITY_ID "$AUDIT_CAPABILITY_ID"
  [[ "$AUDIT_CERT_DIR" == "$CERT_DIR" && -d "$AUDIT_CERT_DIR" && ! -L "$AUDIT_CERT_DIR" ]] || die "prepared certificate directory is invalid"
  [[ "$AUDIT_RUNTIME_DIR" == "$RUNTIME_DIR" && -d "$AUDIT_RUNTIME_DIR" && ! -L "$AUDIT_RUNTIME_DIR" ]] || die "prepared runtime directory is invalid"
  [[ "$AUDIT_ARTIFACT_DIR" == "$ARTIFACT_DIR" && -d "$AUDIT_ARTIFACT_DIR" && ! -L "$AUDIT_ARTIFACT_DIR" ]] || die "prepared artifact directory is invalid"
  [[ "$AUDIT_BIN_DIR" == "$BIN_DIR" && -d "$AUDIT_BIN_DIR" && ! -L "$AUDIT_BIN_DIR" ]] || die "prepared binary directory is invalid"
  [[ "$AUDIT_PRIVATE_DIR" == "$PRIVATE_DIR" && -d "$AUDIT_PRIVATE_DIR" && ! -L "$AUDIT_PRIVATE_DIR" ]] || die "prepared private directory is invalid"
  [[ "$AUDIT_DRIVER_DIR" == "$DRIVER_DIR" && -d "$AUDIT_DRIVER_DIR" && ! -L "$AUDIT_DRIVER_DIR" ]] || die "prepared driver directory is invalid"
  [[ "$AUDIT_TENANT_A" == "$TENANT_A" && "$AUDIT_TENANT_B" == "$TENANT_B" ]] || die "prepared tenant identities are invalid"
  [[ "$AUDIT_HOST_UID" =~ ^[0-9]+$ && "$AUDIT_HOST_GID" =~ ^[0-9]+$ ]] || die "prepared host UID/GID are malformed"
  [[ "$AUDIT_HOST_UID" == "$(id -u)" && "$AUDIT_HOST_GID" == "$(id -g)" ]] || die "prepared state belongs to a different invoking UID/GID"
  [[ "$AUDIT_TEST_A_NAME" == "cl002-f50-a-${AUDIT_GIT_SHA:0:12}" && "$AUDIT_TEST_B_NAME" == "cl002-f50-b-${AUDIT_GIT_SHA:0:12}" ]] || die "prepared marker names are invalid"
  [[ "$AUDIT_COMPOSE_PROJECT" =~ ^probectl-audit-[0-9a-f]{12}-[0-9]+-[0-9]+$ ]] || die "prepared Compose project name is invalid"
  [[ "$AUDIT_CONTROL_IMAGE" == "probectl-control:completeness-${AUDIT_GIT_SHA:0:12}" ]] || die "prepared control image name is invalid"
  [[ "$AUDIT_CLI_IMAGE" == "probectl-cli:completeness-${AUDIT_GIT_SHA:0:12}" ]] || die "prepared CLI image name is invalid"
  [[ "$AUDIT_BROWSER_IMAGE" == "probectl-browser:completeness-${AUDIT_GIT_SHA:0:12}" ]] || die "prepared browser image name is invalid"
  if [[ -n "$AUDIT_BROWSER_DRIVER_PATH" ]]; then
    [[ "$AUDIT_BROWSER_DRIVER_PATH" == "${AUDIT_DRIVER_DIR}/browser-driver.mjs" && -f "$AUDIT_BROWSER_DRIVER_PATH" && ! -L "$AUDIT_BROWSER_DRIVER_PATH" && "$AUDIT_BROWSER_SCRIPT" == "/audit/drivers/browser-driver.mjs" ]] ||
      die "prepared custom browser driver is invalid"
  else
    [[ "$AUDIT_BROWSER_SCRIPT" == "/audit/scripts/completeness_audit_browser.mjs" ]] || die "prepared built-in browser driver path is invalid"
  fi
  if [[ -n "$AUDIT_CAPABILITY_DRIVER_PATH" ]]; then
    [[ "$AUDIT_CAPABILITY_DRIVER_PATH" == "${PRIVATE_DIR}/capability-driver" && -f "$AUDIT_CAPABILITY_DRIVER_PATH" && ! -L "$AUDIT_CAPABILITY_DRIVER_PATH" ]] || die "prepared capability driver is invalid"
    [[ "$AUDIT_CAPABILITY_DRIVER_SOURCE_PATH" != /* && "$AUDIT_CAPABILITY_DRIVER_SOURCE_PATH" != *".."* && -f "${AUDIT_SOURCE_DIR}/${AUDIT_CAPABILITY_DRIVER_SOURCE_PATH}" ]] || die "capability driver is not source-bound"
    [[ "$AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA" =~ ^[0-9a-f]{40}$ ]] || die "capability driver Git blob identity is malformed"
  else
    [[ -z "$AUDIT_CAPABILITY_DRIVER_SOURCE_PATH" && -z "$AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA" ]] || die "unexpected capability-driver source identity"
  fi
  if [[ -n "$AUDIT_BROWSER_DRIVER_PATH" ]]; then
    [[ "$AUDIT_BROWSER_DRIVER_SOURCE_PATH" != /* && "$AUDIT_BROWSER_DRIVER_SOURCE_PATH" != *".."* && -f "${AUDIT_SOURCE_DIR}/${AUDIT_BROWSER_DRIVER_SOURCE_PATH}" ]] || die "browser driver is not source-bound"
  else
    [[ -z "$AUDIT_BROWSER_DRIVER_SOURCE_PATH" && -z "$AUDIT_BROWSER_DRIVER_GIT_BLOB_SHA" ]] || die "unexpected browser-driver source identity"
  fi
  [[ "$AUDIT_SOURCE_DIR" == "${PRIVATE_DIR}/source-${AUDIT_GIT_SHA}" && -d "$AUDIT_SOURCE_DIR" && ! -L "$AUDIT_SOURCE_DIR" ]] ||
    die "prepared immutable source directory is invalid"
  [[ "$AUDIT_SOURCE_ARCHIVE" == "${PRIVATE_DIR}/source-${AUDIT_GIT_SHA}.tar" && -f "$AUDIT_SOURCE_ARCHIVE" && ! -L "$AUDIT_SOURCE_ARCHIVE" ]] ||
    die "prepared immutable source archive is invalid"
  [[ "$AUDIT_COMPOSE_FILE" == "${AUDIT_SOURCE_DIR}/deploy/compose/completeness-audit.yml" && -f "$AUDIT_COMPOSE_FILE" && ! -L "$AUDIT_COMPOSE_FILE" ]] ||
    die "prepared immutable Compose file is invalid"
}

compose() {
  docker compose --env-file "$ENV_FILE" -p "$AUDIT_COMPOSE_PROJECT" -f "$AUDIT_COMPOSE_FILE" "$@"
}

assert_exact_clean_source() {
  [[ "$(git -C "$REPO_ROOT" rev-parse HEAD)" == "$AUDIT_GIT_SHA" ]] || die "live checkout HEAD changed after prepare"
  [[ "$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')" == "$AUDIT_TREE_SHA" ]] || die "live checkout tree changed after prepare"
  [[ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal)" ]] || die "live checkout changed after prepare"
}

assert_frozen_harness() {
  local fresh_archive fresh_source
  fresh_archive="$(mktemp "${PRIVATE_DIR}/source-check.XXXXXX.tar")"
  fresh_source="$(mktemp -d "${PRIVATE_DIR}/source-check.XXXXXX")"
  git -C "$REPO_ROOT" archive --format=tar "$AUDIT_GIT_SHA" >"$fresh_archive"
  [[ "sha256:$(sha256_file "$AUDIT_SOURCE_ARCHIVE")" == "$AUDIT_SOURCE_ARCHIVE_SHA256" ]] || die "persisted source archive changed after prepare"
  [[ "sha256:$(sha256_file "$fresh_archive")" == "$AUDIT_SOURCE_ARCHIVE_SHA256" ]] || die "fresh Git archive does not match prepared source archive"
  tar -xf "$fresh_archive" -C "$fresh_source"
  diff -qr "$fresh_source" "$AUDIT_SOURCE_DIR" >/dev/null || die "an archived harness file changed after prepare"
  rm -f "$fresh_archive"
  [[ "$fresh_source" == "${PRIVATE_DIR}/source-check."* ]] || die "refusing unsafe temporary-source cleanup"
  rm -rf -- "$fresh_source"
}

assert_frozen_drivers() {
  if [[ -n "$AUDIT_CAPABILITY_DRIVER_PATH" ]]; then
    [[ "sha256:$(sha256_file "$AUDIT_CAPABILITY_DRIVER_PATH")" == "$AUDIT_CAPABILITY_DRIVER_SHA256" ]] || die "frozen capability driver changed after prepare"
    [[ "sha256:$(sha256_file "${AUDIT_SOURCE_DIR}/${AUDIT_CAPABILITY_DRIVER_SOURCE_PATH}")" == "$AUDIT_CAPABILITY_DRIVER_SHA256" ]] || die "capability driver does not match exact source"
    [[ "$(git -C "$REPO_ROOT" rev-parse --verify "${AUDIT_GIT_SHA}:${AUDIT_CAPABILITY_DRIVER_SOURCE_PATH}")" == "$AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA" ]] || die "capability driver Git blob identity changed"
  fi
  if [[ -n "$AUDIT_BROWSER_DRIVER_PATH" ]]; then
    [[ "sha256:$(sha256_file "$AUDIT_BROWSER_DRIVER_PATH")" == "$AUDIT_BROWSER_DRIVER_SHA256" ]] || die "frozen browser driver changed after prepare"
    [[ "sha256:$(sha256_file "${AUDIT_SOURCE_DIR}/${AUDIT_BROWSER_DRIVER_SOURCE_PATH}")" == "$AUDIT_BROWSER_DRIVER_SHA256" ]] || die "browser driver does not match exact source"
  fi
}

prepare() {
  need docker
  need htpasswd
  static_checks

  # Build from an immutable tracked snapshot, never the live worktree. A
  # concurrent editor or ignored generated file therefore cannot change the
  # bytes attributed to HEAD after the clean-tree check.
  SOURCE_DIR="${PRIVATE_DIR}/source-${GIT_SHA}"
  AUDIT_SOURCE_ARCHIVE="${PRIVATE_DIR}/source-${GIT_SHA}.tar"
  mkdir -p "$SOURCE_DIR"
  git -C "$REPO_ROOT" archive --format=tar "$GIT_SHA" >"$AUDIT_SOURCE_ARCHIVE"
  chmod 0400 "$AUDIT_SOURCE_ARCHIVE"
  tar -xf "$AUDIT_SOURCE_ARCHIVE" -C "$SOURCE_DIR"
  AUDIT_SOURCE_ARCHIVE_SHA256="sha256:$(sha256_file "$AUDIT_SOURCE_ARCHIVE")"
  AUDIT_SOURCE_DIR="$SOURCE_DIR"
  AUDIT_COMPOSE_FILE="${SOURCE_DIR}/deploy/compose/completeness-audit.yml"
  AUDIT_GIT_SHA="$GIT_SHA"
  AUDIT_TREE_SHA="$TREE_SHA"
  AUDIT_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  AUDIT_CERT_DIR="$CERT_DIR"
  AUDIT_RUNTIME_DIR="$RUNTIME_DIR"
  AUDIT_ARTIFACT_DIR="$ARTIFACT_DIR"
  AUDIT_BIN_DIR="$BIN_DIR"
  AUDIT_PRIVATE_DIR="$PRIVATE_DIR"
  AUDIT_DRIVER_DIR="$DRIVER_DIR"
  AUDIT_TENANT_A="$TENANT_A"
  AUDIT_TENANT_B="$TENANT_B"
  AUDIT_HOST_UID="$(id -u)"
  AUDIT_HOST_GID="$(id -g)"

  AUDIT_COMPOSE_PROJECT="probectl-audit-${SHA12}-$$-${RANDOM}"
  AUDIT_CONTROL_IMAGE="probectl-control:completeness-${SHA12}"
  AUDIT_CLI_IMAGE="probectl-cli:completeness-${SHA12}"
  AUDIT_BROWSER_IMAGE="probectl-browser:completeness-${SHA12}"
  AUDIT_TEST_A_NAME="cl002-f50-a-${SHA12}"
  AUDIT_TEST_B_NAME="cl002-f50-b-${SHA12}"
  AUDIT_ITEM="${PROBECTL_AUDIT_ITEM:-CL-002}"
  AUDIT_CAPABILITY_ID="${PROBECTL_AUDIT_CAPABILITY_ID:-F50}"
  require_safe_id PROBECTL_AUDIT_ITEM "$AUDIT_ITEM"
  require_safe_id PROBECTL_AUDIT_CAPABILITY_ID "$AUDIT_CAPABILITY_ID"
  [[ -f "${AUDIT_SOURCE_DIR}/${AUDIT_AUTHORITY_REL}" && ! -L "${AUDIT_SOURCE_DIR}/${AUDIT_AUTHORITY_REL}" ]] ||
    die "exact-tree delivery-audit authority registry is missing"
  jq -e --arg item "$AUDIT_ITEM" --arg capability "$AUDIT_CAPABILITY_ID" '
    .schema=="probectl.delivery-audit-authority/v1" and
    ([.executable_protocols[] | select(.item==$item and .capability_id==$capability and .mode=="tenant_plane")]|length)==1
  ' "${AUDIT_SOURCE_DIR}/${AUDIT_AUTHORITY_REL}" >/dev/null ||
    die "requested item/capability has no unique tenant-plane executable protocol in the exact-tree authority registry"
  AUDIT_CAPABILITY_DRIVER_PATH=""
  AUDIT_CAPABILITY_DRIVER_SOURCE_PATH=""
  AUDIT_CAPABILITY_DRIVER_SHA256=""
  AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA=""
  AUDIT_BROWSER_DRIVER_PATH=""
  AUDIT_BROWSER_DRIVER_SOURCE_PATH=""
  AUDIT_BROWSER_DRIVER_SHA256=""
  AUDIT_BROWSER_DRIVER_GIT_BLOB_SHA=""
  AUDIT_BROWSER_SCRIPT="/audit/scripts/completeness_audit_browser.mjs"
  if [[ -n "${PROBECTL_AUDIT_CAPABILITY_DRIVER:-}" ]]; then
    require_safe_path "$PROBECTL_AUDIT_CAPABILITY_DRIVER"
    driver_abs="$(CDPATH= cd -- "$(dirname -- "$PROBECTL_AUDIT_CAPABILITY_DRIVER")" && pwd -P)/$(basename -- "$PROBECTL_AUDIT_CAPABILITY_DRIVER")"
    [[ "$driver_abs" == "${REPO_ROOT}/"* && -f "$driver_abs" && ! -L "$driver_abs" ]] ||
      die "capability driver must be a tracked regular file beneath the repository root"
    AUDIT_CAPABILITY_DRIVER_SOURCE_PATH="${driver_abs#${REPO_ROOT}/}"
    git -C "$REPO_ROOT" ls-files --error-unmatch "$AUDIT_CAPABILITY_DRIVER_SOURCE_PATH" >/dev/null 2>&1 ||
      die "capability driver is not tracked at the audited SHA"
    [[ -f "${AUDIT_SOURCE_DIR}/${AUDIT_CAPABILITY_DRIVER_SOURCE_PATH}" && ! -L "${AUDIT_SOURCE_DIR}/${AUDIT_CAPABILITY_DRIVER_SOURCE_PATH}" ]] ||
      die "capability driver is absent from the immutable source archive"
    AUDIT_CAPABILITY_DRIVER_PATH="${PRIVATE_DIR}/capability-driver"
    install -m 0500 "${AUDIT_SOURCE_DIR}/${AUDIT_CAPABILITY_DRIVER_SOURCE_PATH}" "$AUDIT_CAPABILITY_DRIVER_PATH"
    AUDIT_CAPABILITY_DRIVER_SHA256="sha256:$(sha256_file "$AUDIT_CAPABILITY_DRIVER_PATH")"
    AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA="$(git -C "$REPO_ROOT" rev-parse --verify "${GIT_SHA}:${AUDIT_CAPABILITY_DRIVER_SOURCE_PATH}")"
    [[ "$AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA" =~ ^[0-9a-f]{40}$ ]] || die "capability driver is not a tracked Git blob at the audited SHA"
  elif [[ "$AUDIT_CAPABILITY_ID" != "F50" ]]; then
    die "capability $AUDIT_CAPABILITY_ID needs PROBECTL_AUDIT_CAPABILITY_DRIVER during prepare"
  fi
  if [[ -n "${PROBECTL_AUDIT_BROWSER_DRIVER:-}" ]]; then
    die "arbitrary browser code is not accepted; use the fixed browser driver plus a declarative capability manifest"
  fi
  unset PROBECTL_AUDIT_CAPABILITY_DRIVER
  unset PROBECTL_AUDIT_BROWSER_DRIVER
  DEX_AUDIT_PASSWORD="$(openssl rand -hex 24)"
  DEX_AUDIT_PASSWORD_HASH="$(htpasswd -bnBC 12 audit "$DEX_AUDIT_PASSWORD" | cut -d: -f2)"
  PROMETHEUS_PASSWORD="$(openssl rand -hex 24)"
  PROMETHEUS_PASSWORD_HASH="$(htpasswd -bnBC 12 audit "$PROMETHEUS_PASSWORD" | cut -d: -f2)"
  POSTGRES_PASSWORD="$(openssl rand -hex 24)"
  KAFKA_STORE_PASSWORD="$(openssl rand -hex 24)"
  KAFKA_SASL_PASSWORD="$(openssl rand -hex 24)"
  CLICKHOUSE_PASSWORD="$(openssl rand -hex 24)"
  DEX_CLIENT_SECRET="$(openssl rand -hex 32)"
  PROBECTL_SESSION_HMAC_KEY="$(openssl rand -hex 32)"

  for env_name in AUDIT_COMPOSE_PROJECT AUDIT_CONTROL_IMAGE AUDIT_CLI_IMAGE AUDIT_BROWSER_IMAGE \
    AUDIT_CERT_DIR AUDIT_RUNTIME_DIR AUDIT_ARTIFACT_DIR AUDIT_BIN_DIR AUDIT_PRIVATE_DIR AUDIT_DRIVER_DIR AUDIT_SOURCE_DIR AUDIT_SOURCE_ARCHIVE \
    AUDIT_SOURCE_ARCHIVE_SHA256 AUDIT_COMPOSE_FILE \
    AUDIT_GIT_SHA AUDIT_TREE_SHA AUDIT_STARTED_AT AUDIT_TENANT_A AUDIT_TENANT_B AUDIT_HOST_UID AUDIT_HOST_GID AUDIT_TEST_A_NAME AUDIT_TEST_B_NAME AUDIT_ITEM \
    AUDIT_CAPABILITY_ID AUDIT_CAPABILITY_DRIVER_PATH AUDIT_CAPABILITY_DRIVER_SOURCE_PATH AUDIT_CAPABILITY_DRIVER_SHA256 AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA AUDIT_BROWSER_SCRIPT \
    AUDIT_BROWSER_DRIVER_PATH AUDIT_BROWSER_DRIVER_SOURCE_PATH AUDIT_BROWSER_DRIVER_SHA256 AUDIT_BROWSER_DRIVER_GIT_BLOB_SHA POSTGRES_PASSWORD \
    KAFKA_STORE_PASSWORD KAFKA_SASL_PASSWORD CLICKHOUSE_PASSWORD PROMETHEUS_PASSWORD DEX_CLIENT_SECRET DEX_AUDIT_PASSWORD \
    DEX_AUDIT_PASSWORD_HASH PROBECTL_SESSION_HMAC_KEY; do
    require_env_value "$env_name" "${!env_name}"
  done

  umask 077
  {
    printf "AUDIT_COMPOSE_PROJECT='%s'\n" "$AUDIT_COMPOSE_PROJECT"
    printf "AUDIT_CONTROL_IMAGE='%s'\n" "$AUDIT_CONTROL_IMAGE"
    printf "AUDIT_CLI_IMAGE='%s'\n" "$AUDIT_CLI_IMAGE"
    printf "AUDIT_BROWSER_IMAGE='%s'\n" "$AUDIT_BROWSER_IMAGE"
    printf "AUDIT_CERT_DIR='%s'\n" "$AUDIT_CERT_DIR"
    printf "AUDIT_RUNTIME_DIR='%s'\n" "$AUDIT_RUNTIME_DIR"
    printf "AUDIT_ARTIFACT_DIR='%s'\n" "$AUDIT_ARTIFACT_DIR"
    printf "AUDIT_BIN_DIR='%s'\n" "$AUDIT_BIN_DIR"
    printf "AUDIT_PRIVATE_DIR='%s'\n" "$AUDIT_PRIVATE_DIR"
    printf "AUDIT_DRIVER_DIR='%s'\n" "$AUDIT_DRIVER_DIR"
    printf "AUDIT_SOURCE_DIR='%s'\n" "$AUDIT_SOURCE_DIR"
    printf "AUDIT_SOURCE_ARCHIVE='%s'\n" "$AUDIT_SOURCE_ARCHIVE"
    printf "AUDIT_SOURCE_ARCHIVE_SHA256='%s'\n" "$AUDIT_SOURCE_ARCHIVE_SHA256"
    printf "AUDIT_COMPOSE_FILE='%s'\n" "$AUDIT_COMPOSE_FILE"
    printf "AUDIT_GIT_SHA='%s'\n" "$AUDIT_GIT_SHA"
    printf "AUDIT_TREE_SHA='%s'\n" "$AUDIT_TREE_SHA"
    printf "AUDIT_STARTED_AT='%s'\n" "$AUDIT_STARTED_AT"
    printf "AUDIT_TENANT_A='%s'\n" "$AUDIT_TENANT_A"
    printf "AUDIT_TENANT_B='%s'\n" "$AUDIT_TENANT_B"
    printf "AUDIT_HOST_UID='%s'\n" "$AUDIT_HOST_UID"
    printf "AUDIT_HOST_GID='%s'\n" "$AUDIT_HOST_GID"
    printf "AUDIT_TEST_A_NAME='%s'\n" "$AUDIT_TEST_A_NAME"
    printf "AUDIT_TEST_B_NAME='%s'\n" "$AUDIT_TEST_B_NAME"
    printf "AUDIT_ITEM='%s'\n" "$AUDIT_ITEM"
    printf "AUDIT_CAPABILITY_ID='%s'\n" "$AUDIT_CAPABILITY_ID"
    printf "AUDIT_CAPABILITY_DRIVER_PATH='%s'\n" "$AUDIT_CAPABILITY_DRIVER_PATH"
    printf "AUDIT_CAPABILITY_DRIVER_SOURCE_PATH='%s'\n" "$AUDIT_CAPABILITY_DRIVER_SOURCE_PATH"
    printf "AUDIT_CAPABILITY_DRIVER_SHA256='%s'\n" "$AUDIT_CAPABILITY_DRIVER_SHA256"
    printf "AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA='%s'\n" "$AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA"
    printf "AUDIT_BROWSER_SCRIPT='%s'\n" "$AUDIT_BROWSER_SCRIPT"
    printf "AUDIT_BROWSER_DRIVER_PATH='%s'\n" "$AUDIT_BROWSER_DRIVER_PATH"
    printf "AUDIT_BROWSER_DRIVER_SOURCE_PATH='%s'\n" "$AUDIT_BROWSER_DRIVER_SOURCE_PATH"
    printf "AUDIT_BROWSER_DRIVER_SHA256='%s'\n" "$AUDIT_BROWSER_DRIVER_SHA256"
    printf "AUDIT_BROWSER_DRIVER_GIT_BLOB_SHA='%s'\n" "$AUDIT_BROWSER_DRIVER_GIT_BLOB_SHA"
    printf "POSTGRES_PASSWORD='%s'\n" "$POSTGRES_PASSWORD"
    printf "KAFKA_STORE_PASSWORD='%s'\n" "$KAFKA_STORE_PASSWORD"
    printf "KAFKA_SASL_PASSWORD='%s'\n" "$KAFKA_SASL_PASSWORD"
    printf "CLICKHOUSE_USER='probectl'\n"
    printf "CLICKHOUSE_PASSWORD='%s'\n" "$CLICKHOUSE_PASSWORD"
    printf "PROMETHEUS_USER='audit'\n"
    printf "PROMETHEUS_PASSWORD='%s'\n" "$PROMETHEUS_PASSWORD"
    printf "DEX_CLIENT_SECRET='%s'\n" "$DEX_CLIENT_SECRET"
    printf "DEX_AUDIT_PASSWORD='%s'\n" "$DEX_AUDIT_PASSWORD"
    printf "DEX_AUDIT_PASSWORD_HASH='%s'\n" "$DEX_AUDIT_PASSWORD_HASH"
    printf "PROBECTL_SESSION_HMAC_KEY='%s'\n" "$PROBECTL_SESSION_HMAC_KEY"
  } > "$ENV_FILE"
  chmod 0600 "$ENV_FILE"

  jq -n --arg username 'audit' --arg password "$PROMETHEUS_PASSWORD" \
    '{username:$username,password:$password}' >"${PRIVATE_DIR}/prom-probe-basic-auth.json"
  jq -n --arg username 'probectl' --arg password "$CLICKHOUSE_PASSWORD" \
    '{username:$username,password:$password}' >"${PRIVATE_DIR}/ch-probe-basic-auth.json"
  chmod 0600 "${PRIVATE_DIR}/prom-probe-basic-auth.json" "${PRIVATE_DIR}/ch-probe-basic-auth.json"

  {
    printf '%s\n' 'tls_server_config:'
    printf '%s\n' '  cert_file: /audit/pki/prometheus/tls.crt'
    printf '%s\n' '  key_file: /audit/pki/prometheus/tls.key'
    printf '%s\n' '  min_version: TLS12'
    printf '%s\n' 'basic_auth_users:'
    printf '  audit: %s\n' "$PROMETHEUS_PASSWORD_HASH"
  } > "${RUNTIME_DIR}/prometheus-web.yml"
  chmod 0600 "${RUNTIME_DIR}/prometheus-web.yml"

  log "minting a disposable <=6h audit CA"
  (cd "$SOURCE_DIR" && go run ./cmd/probectl-delivery-audit certs --out "$CERT_DIR" --ttl 6h) \
    > "${RUNTIME_DIR}/certificate-command.json"

  log "building exact-SHA release images (empty GO_TAGS, real embedded Vite UI)"
  docker build -f "${SOURCE_DIR}/deploy/docker/Dockerfile" "$SOURCE_DIR" \
    --build-arg COMPONENT=probectl-control --build-arg GO_TAGS= \
    --build-arg VERSION="audit-${SHA12}" --build-arg COMMIT="$GIT_SHA" --build-arg DATE="$COMMIT_DATE" \
    -t "$AUDIT_CONTROL_IMAGE"
  docker build -f "${SOURCE_DIR}/deploy/docker/Dockerfile" "$SOURCE_DIR" \
    --build-arg COMPONENT=probectl --build-arg GO_TAGS= \
    --build-arg VERSION="audit-${SHA12}" --build-arg COMMIT="$GIT_SHA" --build-arg DATE="$COMMIT_DATE" \
    -t "$AUDIT_CLI_IMAGE"
  docker build -f "${SOURCE_DIR}/browser-worker/Dockerfile" "${SOURCE_DIR}/browser-worker" -t "$AUDIT_BROWSER_IMAGE"

  local audit_goarch
  audit_goarch="$(docker image inspect --format '{{.Architecture}}' "$AUDIT_CLI_IMAGE")"
  [[ "$audit_goarch" == "amd64" || "$audit_goarch" == "arm64" ]] || die "unsupported audit CLI image architecture: $audit_goarch"
  (cd "$SOURCE_DIR" && GOOS=linux GOARCH="$audit_goarch" CGO_ENABLED=0 go build -trimpath -o "${BIN_DIR}/completeness-store-probe" \
    ./deploy/compose/completeness-audit/probe)
  (cd "$SOURCE_DIR" && CGO_ENABLED=0 go build -trimpath -o "${BIN_DIR}/probectl-delivery-audit" \
    ./cmd/probectl-delivery-audit)
  chmod 0500 "${BIN_DIR}/completeness-store-probe" "${BIN_DIR}/probectl-delivery-audit"

  cli_container="$(docker create "$AUDIT_CLI_IMAGE")"
  docker cp "${cli_container}:/usr/local/bin/app" "${BIN_DIR}/probectl"
  docker rm "$cli_container" >/dev/null
  control_container="$(docker create "$AUDIT_CONTROL_IMAGE")"
  docker cp "${control_container}:/usr/local/bin/app" "${BIN_DIR}/probectl-control"
  docker rm "$control_container" >/dev/null
  chmod 0500 "${BIN_DIR}/probectl" "${BIN_DIR}/probectl-control"
  cli_sha="$(sha256_file "${BIN_DIR}/probectl")"
  cli_version="$(docker run --rm "$AUDIT_CLI_IMAGE" --json version)"
  control_version="$(docker run --rm "$AUDIT_CONTROL_IMAGE" version)"
  [[ "$(jq -r .commit <<<"$cli_version")" == "$GIT_SHA" ]] || die "release CLI commit stamp mismatch"
  [[ "$control_version" == *"$GIT_SHA"* ]] || die "release control commit stamp mismatch"
  if go version -m "${BIN_DIR}/probectl" "${BIN_DIR}/probectl-control" | rg -q $'build\t-tags='; then
    die "release CLI/control binary recorded non-empty Go build tags"
  fi

  control_image_id="$(docker image inspect --format '{{.Id}}' "$AUDIT_CONTROL_IMAGE")"
  cli_image_id="$(docker image inspect --format '{{.Id}}' "$AUDIT_CLI_IMAGE")"
  browser_image_id="$(docker image inspect --format '{{.Id}}' "$AUDIT_BROWSER_IMAGE")"
  if [[ -n "$AUDIT_CAPABILITY_DRIVER_PATH" ]]; then
    capability_driver_json="$(jq -nc --arg runtime "$AUDIT_CAPABILITY_DRIVER_PATH" --arg source "$AUDIT_CAPABILITY_DRIVER_SOURCE_PATH" --arg sha "$AUDIT_CAPABILITY_DRIVER_SHA256" --arg blob "$AUDIT_CAPABILITY_DRIVER_GIT_BLOB_SHA" \
      '{kind:"source_bound",runtime_path:$runtime,source_path:$source,sha256:$sha,git_blob_sha:$blob}')"
  else
    capability_driver_json='{"kind":"builtin","runtime_path":"scripts/run_completeness_audit.sh#run_f50_capability"}'
  fi
  harness_json="$(jq -nc --argjson capability_driver "$capability_driver_json" \
    '{mode:"tenant_plane",browser_auth_mode:"tenant_oidc",cli_auth_mode:"tenant_mcp_bearer",provider_compatibility_validated:false,capability_driver:$capability_driver,browser_driver:{kind:"builtin",runtime_path:"scripts/completeness_audit_browser.mjs"}}')"
  jq -n \
    --arg schema 'probectl.delivery-audit-stack/v1' \
    --arg git_sha "$GIT_SHA" --arg tree_sha "$TREE_SHA" \
    --arg control_image "$AUDIT_CONTROL_IMAGE" --arg control_image_id "$control_image_id" \
    --arg cli_image "$AUDIT_CLI_IMAGE" --arg cli_image_id "$cli_image_id" \
    --arg cli_sha256 "sha256:${cli_sha}" \
    --arg browser_image "$AUDIT_BROWSER_IMAGE" --arg browser_image_id "$browser_image_id" \
    --argjson harness "$harness_json" \
    '{schema:$schema,source:{git_sha:$git_sha,tree_sha:$tree_sha,dirty:false},release:{control:{image:$control_image,image_id:$control_image_id,build_tags:[],dev_auth:false,embedded_vite_ui:true},cli:{image:$cli_image,image_id:$cli_image_id,sha256:$cli_sha256,build_tags:[],dev_auth:false},browser:{image:$browser_image,image_id:$browser_image_id,engine:"webkit",version:"1.55.1"}},services:{control:{version:$git_sha,running:false,real_service:true,tls_configured:true,authentication_configured:true},dex:{version:"2.45.1",running:false,real_service:true,tls_configured:true,authentication_configured:true},postgres:{version:"16",running:false,real_service:true,tls_configured:true,authentication_configured:true},kafka:{version:"3.9.0",running:false,real_service:true,tls_configured:true,authentication_configured:true},clickhouse:{version:"24.8",running:false,real_service:true,tls_configured:true,authentication_configured:true},prometheus:{version:"3.1.0",running:false,real_service:true,tls_configured:true,authentication_configured:true}},network:{internal:true,published_ports:0},credential_transport:{database:"owner-only PGPASSFILE at /var/lib/probectl/pgpass (uid 65532 gid 65532 mode 0600)",kafka:"SASL_SSL credential volume",clickhouse:"origin-pinned Basic Auth from /run/secrets/ch-basic-auth.json (uid 65532 gid 65532 mode 0600)",prometheus:"origin-pinned Basic Auth from /run/secrets/prom-basic-auth.json (uid 65532 gid 65532 mode 0600)"},runtime:{tls_private_key_files:{}},harness:$harness,limitations:["Path/flow/eBPF/endpoint ClickHouse modes are outside the bounded F50 OTLP path and remain memory. Kafka reader isolation is not claimed; Prometheus query isolation is enforced by the tenant-forcing release API and must be proven by the product-pipeline observation."]}' \
    > "${ARTIFACT_DIR}/stack-inventory.json"
  chmod 0644 "${ARTIFACT_DIR}/stack-inventory.json"
  if [[ -n "$AUDIT_CAPABILITY_DRIVER_PATH" ]]; then
    jq --arg path "$AUDIT_CAPABILITY_DRIVER_SOURCE_PATH" --arg sha "$AUDIT_CAPABILITY_DRIVER_SHA256" \
      '.limitations += [("Source-bound custom capability driver: " + $path + " " + $sha)]' \
      "${ARTIFACT_DIR}/stack-inventory.json" >"${ARTIFACT_DIR}/stack-inventory.json.next"
    mv "${ARTIFACT_DIR}/stack-inventory.json.next" "${ARTIFACT_DIR}/stack-inventory.json"
  fi
  printf '%s\n' "$STATE_DIR" > "${STATE_DIR}/STATE_PATH"
  log "prepared state: $STATE_DIR"
}

cleanup_stack() {
  if [[ "${STACK_ACTIVE:-0}" == "1" ]]; then
    log "tearing down disposable Compose project ${AUDIT_COMPOSE_PROJECT}"
    compose --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
    STACK_ACTIVE=0
  fi
}

remove_bearer_tokens() {
  [[ "$PRIVATE_DIR" == "${STATE_DIR}/private" ]] || die "refusing unsafe bearer-token cleanup"
  rm -f "${PRIVATE_DIR}/token-a" "${PRIVATE_DIR}/token-b" \
    "${PRIVATE_DIR}/otlp-create-a.json" "${PRIVATE_DIR}/otlp-create-b.json" \
    "${PRIVATE_DIR}/product-query.err" "${PRIVATE_DIR}/product-query.tmp"
}

cleanup_run_exit() {
  cleanup_stack
  # A failed run deliberately retains the prepared env and leaf keys so the
  # separable run can be diagnosed/retried, but bearer tokens are never useful
  # across a fresh stack and are always destroyed on exit.
  remove_bearer_tokens
}

seed_two_tenants() {
  log "seeding two tenants, one same-email user per tenant, and separate admin roles"
  compose exec -T postgres \
    psql "host=postgres port=5432 dbname=probectl user=probectl sslmode=verify-full sslrootcert=/audit/pki/ca.crt" \
    -v ON_ERROR_STOP=1 <<SQL
INSERT INTO tenants (id, slug, name, status) VALUES
  ('$TENANT_A', 'audit-a', 'Completeness Audit A', 'active'),
  ('$TENANT_B', 'audit-b', 'Completeness Audit B', 'active')
ON CONFLICT (id) DO UPDATE SET status='active';

BEGIN;
SELECT set_config('probectl.tenant_id', '$TENANT_A', true);
SET LOCAL ROLE probectl_app;
INSERT INTO users (id, tenant_id, email, display_name, status) VALUES
  ('$USER_A', '$TENANT_A', 'audit@probectl.local', 'Completeness Auditor A', 'active')
ON CONFLICT (id) DO UPDATE SET status='active';

INSERT INTO roles (id, tenant_id, slug, name, description, is_system) VALUES
  ('$ROLE_A', '$TENANT_A', 'admin', 'Administrator', 'Disposable audit tenant A administrator', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_key)
  SELECT '$TENANT_A', '$ROLE_A', key FROM permissions
ON CONFLICT (role_id, permission_key) DO NOTHING;

INSERT INTO role_bindings (id, tenant_id, subject_type, subject_id, role_id, scope_type, scope_id) VALUES
  ('aaaaaaaa-0000-4000-8000-000000003001', '$TENANT_A', 'user', '$USER_A', '$ROLE_A', 'tenant', NULL)
ON CONFLICT (id) DO NOTHING;
COMMIT;

BEGIN;
SELECT set_config('probectl.tenant_id', '$TENANT_B', true);
SET LOCAL ROLE probectl_app;
INSERT INTO users (id, tenant_id, email, display_name, status) VALUES
  ('$USER_B', '$TENANT_B', 'audit@probectl.local', 'Completeness Auditor B', 'active')
ON CONFLICT (id) DO UPDATE SET status='active';

INSERT INTO roles (id, tenant_id, slug, name, description, is_system) VALUES
  ('$ROLE_B', '$TENANT_B', 'admin', 'Administrator', 'Disposable audit tenant B administrator', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_key)
  SELECT '$TENANT_B', '$ROLE_B', key FROM permissions
ON CONFLICT (role_id, permission_key) DO NOTHING;

INSERT INTO role_bindings (id, tenant_id, subject_type, subject_id, role_id, scope_type, scope_id) VALUES
  ('bbbbbbbb-0000-4000-8000-000000003002', '$TENANT_B', 'user', '$USER_B', '$ROLE_B', 'tenant', NULL)
ON CONFLICT (id) DO NOTHING;
COMMIT;
SQL
}

mint_token() {
  local tenant="$1" user="$2" token
  token="$(compose exec -T control /usr/local/bin/app mcp-token --tenant "$tenant" --user "$user" --name cl002-delivery-audit | tail -n 1)"
  [[ "$token" =~ ^[A-Za-z0-9_-]{32,}$ ]] || die "control did not return a valid one-time bearer token"
  printf '%s' "$token"
}

cli_json() {
  local tenant="$1" token="$2"
  shift 2
  PROBECTL_API_TOKEN="$token" PROBECTL_TENANT="$tenant" \
    compose --profile tools run --rm -T -e PROBECTL_API_TOKEN -e PROBECTL_TENANT cli --json "$@"
}

mint_otlp_token() {
  local tenant="$1" mcp_token="$2" label="$3" token
  local output="${PRIVATE_DIR}/otlp-create-${label}.json"
  require_safe_id otlp_token_label "$label"
  cli_json "$tenant" "$mcp_token" otlp create-token --body "{\"name\":\"cl002-product-${label}\"}" >"$output"
  jq -e --arg name "cl002-product-${label}" '
    (.id|type)=="string" and (.id|length)>0 and .name==$name and (.token|test("^[0-9a-f]{64}$"))
  ' "$output" >/dev/null || die "release CLI did not mint a valid DB-backed OTLP token for tenant $tenant"
  token="$(jq -er .token "$output")"
  rm -f "$output"
  printf '%s' "$token"
}

generate_product_markers() {
  PRODUCT_METRIC_MARKER_A="$(openssl rand -hex 16)"
  PRODUCT_METRIC_MARKER_B="$(openssl rand -hex 16)"
  PRODUCT_TRACE_MARKER_A="$(openssl rand -hex 16)"
  PRODUCT_TRACE_MARKER_B="$(openssl rand -hex 16)"
  PRODUCT_TRACE_SPAN_ID_A="$(openssl rand -hex 8)"
  PRODUCT_TRACE_SPAN_ID_B="$(openssl rand -hex 8)"
  local values
  values="$(printf '%s\n' "$PRODUCT_METRIC_MARKER_A" "$PRODUCT_METRIC_MARKER_B" "$PRODUCT_TRACE_MARKER_A" "$PRODUCT_TRACE_MARKER_B" | LC_ALL=C sort -u | wc -l | tr -d ' ')"
  [[ "$values" == "4" ]] || die "generated product correlation markers were unexpectedly non-unique"
  export PRODUCT_METRIC_MARKER_A PRODUCT_METRIC_MARKER_B PRODUCT_TRACE_MARKER_A PRODUCT_TRACE_MARKER_B
  export PRODUCT_TRACE_SPAN_ID_A PRODUCT_TRACE_SPAN_ID_B
}

capture_pipeline_counters() {
  local output="$1"
  tool_curl --cacert /audit/pki/ca.crt --fail --silent --show-error --max-filesize 4194304 \
    https://control:8443/metrics >"$output"
  [[ -s "$output" && ! -L "$output" ]] || die "control pipeline counter snapshot is empty or unsafe"
  local signal suffix name count
  for signal in otlp_metrics otlp_traces; do
    for suffix in received_total stored_total malformed_total tenant_rejected_total fairness_shed_total \
      cardinality_dropped_total label_truncated_total unsupported_total dead_lettered_total dropped_total; do
      name="probectl_pipeline_${signal}_${suffix}"
      count="$(awk -v name="$name" '$1==name {n++} END {print n+0}' "$output")"
      [[ "$count" == "1" ]] || die "pipeline counter snapshot contains $count occurrences of $name, want exactly one"
    done
  done
  chmod 0644 "$output"
}

append_product_cli_observation() {
  local tenant="$1" command="$2" path="$3" cli_path="$4" api_path="$5"
  local cli_file="${ARTIFACT_DIR}/${cli_path}" api_file="${ARTIFACT_DIR}/${api_path}"
  local observation="${PRIVATE_DIR}/product-observation.json"
  jq -n \
    --arg tenant "$tenant" --arg command "$command" --arg path "$path" \
    --arg cli_path "$cli_path" --arg cli_sha "sha256:$(sha256_file "$cli_file")" \
    --arg api_path "$api_path" --arg api_sha "sha256:$(sha256_file "$api_file")" \
    '{auth_mode:"tenant_mcp_bearer",tenant:$tenant,command:$command,method:"GET",path:$path,
      expected:"success",cli_exit_status:0,cli_output_artifact:$cli_path,cli_output_sha256:$cli_sha,
      response_artifact:$api_path,status_provenance:"cli_structured_response",status:200,
      success:true,expectation_met:true,response_sha256:$api_sha}' >"$observation"
  jq --slurpfile observation "$observation" '.observations += $observation' \
    "${ARTIFACT_DIR}/cli-transcript.json" >"${ARTIFACT_DIR}/cli-transcript.json.next"
  mv "${ARTIFACT_DIR}/cli-transcript.json.next" "${ARTIFACT_DIR}/cli-transcript.json"
  chmod 0644 "${ARTIFACT_DIR}/cli-transcript.json"
}

record_product_query_time() {
  local tenant="$1" label="$2"
  jq -nc --arg tenant "$tenant" --arg label "$label" --arg observed_at "$(utc_now)" \
    '{tenant:$tenant,label:$label,observed_at:$observed_at}' >>"${PRIVATE_DIR}/product-query-times.ndjson"
}

write_product_api_observation() {
  local tenant="$1" command="$2" path="$3" cli_file="$4" output="$5"
  jq -n --arg tenant "$tenant" --arg command "$command" --arg path "$path" --slurpfile body "$cli_file" \
    '{schema:"probectl.delivery-audit-api-observation/v1",redacted:true,auth_mode:"tenant_mcp_bearer",
      tenant:$tenant,command:$command,method:"GET",path:$path,status:200,body:$body[0]}' >"$output"
  chmod 0644 "$output"
}

capture_product_metric_query() {
  local tenant="$1" token="$2" label="$3" marker="$4" value="$5" want_empty="$6"
  local prefix="product/${tenant}" selector command path encoded
  local cli_path="${prefix}/${label}-cli.json" api_path="${prefix}/${label}-api.json"
  local cli_file="${ARTIFACT_DIR}/${cli_path}" api_file="${ARTIFACT_DIR}/${api_path}"
  local tmp="${PRIVATE_DIR}/product-query.tmp" err_file="${PRIVATE_DIR}/product-query.err" attempt valid=0
  selector="probectl_otlp_completeness_product_marker{marker=\"${marker}\"}"
  command="probectl metric query --query query=${selector}"
  encoded="$(jq -rn --arg value "$selector" '$value|@uri')"
  path="/v1/grafana/api/v1/query?query=${encoded}"
  install -d -m 0755 "${ARTIFACT_DIR}/${prefix}"
  for ((attempt=1; attempt<=60; attempt++)); do
    if cli_json "$tenant" "$token" metric query --query "query=${selector}" >"$tmp" 2>"$err_file"; then
      if [[ "$want_empty" == "true" ]]; then
        if jq -e '.status=="success" and .data.resultType=="vector" and (.data.result|type)=="array" and (.data.result|length)==0' "$tmp" >/dev/null; then
          valid=1
        fi
      elif jq -e --arg tenant "$tenant" --arg marker "$marker" --arg service "completeness-${marker}" --argjson value "$value" '
        .status=="success" and .data.resultType=="vector" and (.data.result|length)==1 and
        .data.result[0].metric.__name__=="probectl_otlp_completeness_product_marker" and
        .data.result[0].metric.tenant_id==$tenant and .data.result[0].metric.marker==$marker and
        .data.result[0].metric.service_name==$service and (.data.result[0].value|length)==2 and
        ((.data.result[0].value[1]|tonumber)==$value)
      ' "$tmp" >/dev/null; then
        valid=1
      fi
    fi
    (( valid == 1 )) && break
    sleep 0.5
  done
  (( valid == 1 )) || die "release CLI metric query did not reach the expected product marker state for tenant $tenant"
  install -m 0644 "$tmp" "$cli_file"
  write_product_api_observation "$tenant" "$command" "$path" "$cli_file" "$api_file"
  append_product_cli_observation "$tenant" "$command" "$path" "$cli_path" "$api_path"
  record_product_query_time "$tenant" "$label"
}

capture_product_trace_query() {
  local tenant="$1" token="$2" label="$3" marker="$4" span_id="$5" want_empty="$6"
  local prefix="product/${tenant}" command path
  local cli_path="${prefix}/${label}-cli.json" api_path="${prefix}/${label}-api.json"
  local cli_file="${ARTIFACT_DIR}/${cli_path}" api_file="${ARTIFACT_DIR}/${api_path}"
  local tmp="${PRIVATE_DIR}/product-query.tmp" err_file="${PRIVATE_DIR}/product-query.err" attempt valid=0
  command="probectl otlp traces --query trace_id=${marker}"
  path="/v1/otlp/traces?trace_id=${marker}"
  install -d -m 0755 "${ARTIFACT_DIR}/${prefix}"
  for ((attempt=1; attempt<=60; attempt++)); do
    if cli_json "$tenant" "$token" otlp traces --query "trace_id=${marker}" >"$tmp" 2>"$err_file"; then
      if [[ "$want_empty" == "true" ]]; then
        if jq -e '(.spans|type)=="array" and (.spans|length)==0' "$tmp" >/dev/null; then
          valid=1
        fi
      elif jq -e --arg tenant "$tenant" --arg trace "$marker" --arg span "$span_id" --arg service "completeness-${marker}" '
        (.spans|length)==1 and .spans[0].tenant_id==$tenant and .spans[0].trace_id==$trace and
        .spans[0].span_id==$span and .spans[0].service==$service and .spans[0].name=="completeness-product-marker"
      ' "$tmp" >/dev/null; then
        valid=1
      fi
    fi
    (( valid == 1 )) && break
    sleep 0.5
  done
  (( valid == 1 )) || die "release CLI trace query did not reach the expected product marker state for tenant $tenant"
  install -m 0644 "$tmp" "$cli_file"
  write_product_api_observation "$tenant" "$command" "$path" "$cli_file" "$api_file"
  append_product_cli_observation "$tenant" "$command" "$path" "$cli_path" "$api_path"
  record_product_query_time "$tenant" "$label"
}

capture_product_queries() {
  local token_a="$1" token_b="$2"
  : >"${PRIVATE_DIR}/product-query-times.ndjson"
  capture_product_metric_query "$TENANT_A" "$token_a" metrics-control-own "$PRODUCT_METRIC_MARKER_A" 84001 false
  capture_product_trace_query "$TENANT_A" "$token_a" traces-control-own "$PRODUCT_TRACE_MARKER_A" "$PRODUCT_TRACE_SPAN_ID_A" false
  capture_product_metric_query "$TENANT_B" "$token_b" metrics-control-own "$PRODUCT_METRIC_MARKER_B" 84002 false
  capture_product_trace_query "$TENANT_B" "$token_b" traces-control-own "$PRODUCT_TRACE_MARKER_B" "$PRODUCT_TRACE_SPAN_ID_B" false
  capture_product_metric_query "$TENANT_A" "$token_a" metrics-control-foreign "$PRODUCT_METRIC_MARKER_B" 84002 true
  capture_product_trace_query "$TENANT_A" "$token_a" traces-control-foreign "$PRODUCT_TRACE_MARKER_B" "$PRODUCT_TRACE_SPAN_ID_B" true
  capture_product_metric_query "$TENANT_B" "$token_b" metrics-control-foreign "$PRODUCT_METRIC_MARKER_A" 84001 true
  capture_product_trace_query "$TENANT_B" "$token_b" traces-control-foreign "$PRODUCT_TRACE_MARKER_A" "$PRODUCT_TRACE_SPAN_ID_A" true
}

product_probe_env_args=(
  -e AUDIT_METRIC_MARKER_A -e AUDIT_METRIC_MARKER_B
  -e AUDIT_TRACE_MARKER_A -e AUDIT_TRACE_MARKER_B
  -e AUDIT_TRACE_SPAN_ID_A -e AUDIT_TRACE_SPAN_ID_B
)

run_product_ingest_probe() {
  local otlp_token_a="$1" otlp_token_b="$2"
  AUDIT_OTLP_TOKEN_A="$otlp_token_a" AUDIT_OTLP_TOKEN_B="$otlp_token_b" \
    AUDIT_METRIC_MARKER_A="$PRODUCT_METRIC_MARKER_A" AUDIT_METRIC_MARKER_B="$PRODUCT_METRIC_MARKER_B" \
    AUDIT_TRACE_MARKER_A="$PRODUCT_TRACE_MARKER_A" AUDIT_TRACE_MARKER_B="$PRODUCT_TRACE_MARKER_B" \
    AUDIT_TRACE_SPAN_ID_A="$PRODUCT_TRACE_SPAN_ID_A" AUDIT_TRACE_SPAN_ID_B="$PRODUCT_TRACE_SPAN_ID_B" \
    compose --profile tools run --rm -T --no-deps \
      -e AUDIT_OTLP_TOKEN_A -e AUDIT_OTLP_TOKEN_B "${product_probe_env_args[@]}" \
      store-probe product-ingest >"${PRIVATE_DIR}/product-ingest.json"
  jq -e --arg a "$TENANT_A" --arg b "$TENANT_B" '
    (.tenants|length)==2 and ([.tenants[].tenant]|sort)==([$a,$b]|sort) and
    all(.tenants[]; .metrics.status==200 and .traces.status==200 and
      .metrics.time_unix_nano>0 and .traces.start_time_unix_nano>0 and .traces.end_time_unix_nano>.traces.start_time_unix_nano and
      (.metrics.observed_at|type)=="string" and (.metrics.observed_at|length)>=20 and
      (.traces.observed_at|type)=="string" and (.traces.observed_at|length)>=20 and
      (.metrics.request_path|type)=="string" and (.metrics.response_path|type)=="string" and
      (.traces.request_path|type)=="string" and (.traces.response_path|type)=="string")
  ' "${PRIVATE_DIR}/product-ingest.json" >/dev/null || die "product OTLP ingest metadata is invalid"
}

run_product_kafka_probe() {
  AUDIT_METRIC_MARKER_A="$PRODUCT_METRIC_MARKER_A" AUDIT_METRIC_MARKER_B="$PRODUCT_METRIC_MARKER_B" \
    AUDIT_TRACE_MARKER_A="$PRODUCT_TRACE_MARKER_A" AUDIT_TRACE_MARKER_B="$PRODUCT_TRACE_MARKER_B" \
    AUDIT_TRACE_SPAN_ID_A="$PRODUCT_TRACE_SPAN_ID_A" AUDIT_TRACE_SPAN_ID_B="$PRODUCT_TRACE_SPAN_ID_B" \
    compose --profile tools run --rm -T --no-deps "${product_probe_env_args[@]}" \
      store-probe product-kafka >"${PRIVATE_DIR}/product-kafka.json"
  jq -e --arg a "$TENANT_A" --arg b "$TENANT_B" '
    (.metrics|length)==2 and (.traces|length)==2 and
    ([.metrics[].tenant]|sort)==([$a,$b]|sort) and ([.traces[].tenant]|sort)==([$a,$b]|sort) and
    all(.metrics[]; .topic=="probectl.otlp.metrics" and .partition>=0 and .offset>=0) and
    all(.traces[]; .topic=="probectl.otlp.traces" and .partition>=0 and .offset>=0)
  ' "${PRIVATE_DIR}/product-kafka.json" >/dev/null || die "product Kafka observation metadata is invalid"
}

run_product_store_probe() {
  AUDIT_METRIC_MARKER_A="$PRODUCT_METRIC_MARKER_A" AUDIT_METRIC_MARKER_B="$PRODUCT_METRIC_MARKER_B" \
    AUDIT_TRACE_MARKER_A="$PRODUCT_TRACE_MARKER_A" AUDIT_TRACE_MARKER_B="$PRODUCT_TRACE_MARKER_B" \
    AUDIT_TRACE_SPAN_ID_A="$PRODUCT_TRACE_SPAN_ID_A" AUDIT_TRACE_SPAN_ID_B="$PRODUCT_TRACE_SPAN_ID_B" \
    compose --profile tools run --rm -T --no-deps "${product_probe_env_args[@]}" \
      store-probe product-stores >"${PRIVATE_DIR}/product-stores.json"
  jq -e --arg a "$TENANT_A" --arg b "$TENANT_B" '
    (.tenants|length)==2 and ([.tenants[].tenant]|sort)==([$a,$b]|sort) and
    all(.tenants[]; .prometheus_http_status==200 and .clickhouse_http_status==200 and
      (.prometheus_observed_at|type)=="string" and (.prometheus_observed_at|length)>=20 and
      (.clickhouse_observed_at|type)=="string" and (.clickhouse_observed_at|length)>=20) and
    .clickhouse_isolation.database=="default" and .clickhouse_isolation.table=="probectl_otel_spans" and
    .clickhouse_isolation.reader_user=="probectl" and .clickhouse_isolation.tenant_setting=="SQL_probectl_tenant" and
    .clickhouse_isolation.tenant_a==$a and .clickhouse_isolation.tenant_b==$b and
    .clickhouse_isolation.tenant_a_response=="product/clickhouse-isolation-tenant-a.jsonl" and
    .clickhouse_isolation.tenant_b_response=="product/clickhouse-isolation-tenant-b.jsonl" and
    .clickhouse_isolation.unset_response=="product/clickhouse-isolation-unset.jsonl" and
    (.clickhouse_isolation.tenant_a_observed_at|type)=="string" and
    (.clickhouse_isolation.tenant_b_observed_at|type)=="string" and
    (.clickhouse_isolation.unset_observed_at|type)=="string" and
    .clickhouse_isolation.seeded_tenant_a_rows>0 and .clickhouse_isolation.seeded_tenant_b_rows>0 and
    .clickhouse_isolation.tenant_a_own_visible_rows>0 and .clickhouse_isolation.tenant_b_own_visible_rows>0 and
    .clickhouse_isolation.tenant_a_to_b_visible_rows==0 and .clickhouse_isolation.tenant_b_to_a_visible_rows==0 and
    .clickhouse_isolation.unset_visible_rows==0 and .clickhouse_isolation.reader_policy_observed==true
  ' "${PRIVATE_DIR}/product-stores.json" >/dev/null || die "actual product ClickHouse setting-scoped proof is invalid"
}

capture_product_group_offset() {
  local signal="$1" tenant="$2" group topic partition offset prefix raw_path typed_path
  local raw_file typed_file tmp="${PRIVATE_DIR}/kafka-group-offset.tmp" current attempt found=0
  case "$signal" in
    metrics) group="otlp-metrics"; topic="probectl.otlp.metrics" ;;
    traces) group="otlp-traces"; topic="probectl.otlp.traces" ;;
    *) die "unknown product Kafka signal: $signal" ;;
  esac
  partition="$(jq -er --arg signal "$signal" --arg tenant "$tenant" '.[$signal][]|select(.tenant==$tenant)|.partition' "${PRIVATE_DIR}/product-kafka.json")"
  offset="$(jq -er --arg signal "$signal" --arg tenant "$tenant" '.[$signal][]|select(.tenant==$tenant)|.offset' "${PRIVATE_DIR}/product-kafka.json")"
  [[ "$partition" =~ ^[0-9]+$ && "$offset" =~ ^[0-9]+$ ]] || die "product Kafka record metadata is malformed"
  for ((attempt=1; attempt<=60; attempt++)); do
    if compose exec -T kafka /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server kafka:9093 \
      --command-config /etc/kafka/secrets/client.properties --describe --group "$group" >"$tmp" 2>"${PRIVATE_DIR}/product-query.err"; then
      current="$(awk -v group="$group" -v topic="$topic" -v partition="$partition" \
        '$1==group && $2==topic && $3==partition {print $4; exit}' "$tmp")"
      if [[ "$current" =~ ^[0-9]+$ ]] && (( current > offset )); then
        found=1
        break
      fi
    fi
    sleep 0.5
  done
  (( found == 1 )) || die "release Kafka group $group did not commit beyond $topic partition $partition offset $offset"
  prefix="product/${tenant}"
  raw_path="${prefix}/${signal}-kafka-group-offset-raw.txt"
  typed_path="${prefix}/${signal}-kafka-group-offset.json"
  raw_file="${ARTIFACT_DIR}/${raw_path}"
  typed_file="${ARTIFACT_DIR}/${typed_path}"
  install -m 0644 "$tmp" "$raw_file"
  jq -n --arg topic "$topic" --arg group "$group" --arg observed_at "$(utc_now)" --arg raw_path "$raw_path" \
    --arg raw_sha "sha256:$(sha256_file "$raw_file")" --argjson partition "$partition" --argjson committed "$current" \
    '{schema:"probectl.delivery-audit-kafka-group-offset/v1",broker_authority:"kafka:9093",
      source:"kafka_consumer_groups_describe",security_protocol:"SASL_SSL",tls_verified:true,sasl_authenticated:true,
      observed_at:$observed_at,topic:$topic,partition:$partition,consumer_group:$group,committed_offset:$committed,
      raw_observation:{path:$raw_path,sha256:$raw_sha}}' >"$typed_file"
  chmod 0644 "$typed_file"
  jq --arg signal "$signal" --arg tenant "$tenant" --arg path "$typed_path" \
    '(.[$signal][]|select(.tenant==$tenant)).group_offset_path=$path' \
    "${PRIVATE_DIR}/product-kafka.json" >"${PRIVATE_DIR}/product-kafka.json.next"
  mv "${PRIVATE_DIR}/product-kafka.json.next" "${PRIVATE_DIR}/product-kafka.json"
}

capture_product_group_offsets() {
  capture_product_group_offset metrics "$TENANT_A"
  capture_product_group_offset metrics "$TENANT_B"
  capture_product_group_offset traces "$TENANT_A"
  capture_product_group_offset traces "$TENANT_B"
}

validate_product_counter_deltas() {
  local before="${ARTIFACT_DIR}/product/pipeline-counters-before.prom"
  local after="${ARTIFACT_DIR}/product/pipeline-counters-after.prom"
  local signal suffix name before_value after_value
  for signal in otlp_metrics otlp_traces; do
    for suffix in received_total stored_total malformed_total tenant_rejected_total fairness_shed_total \
      cardinality_dropped_total label_truncated_total unsupported_total dead_lettered_total dropped_total; do
      name="probectl_pipeline_${signal}_${suffix}"
      before_value="$(awk -v name="$name" '$1==name {print $2}' "$before")"
      after_value="$(awk -v name="$name" '$1==name {print $2}' "$after")"
      [[ -n "$before_value" && -n "$after_value" ]] || die "missing product pipeline counter $name"
      if [[ "$suffix" == "received_total" || "$suffix" == "stored_total" ]]; then
        awk -v before="$before_value" -v after="$after_value" 'BEGIN {exit !((after-before) >= 2)}' ||
          die "$name did not increase by at least the two tenant messages"
      else
        awk -v before="$before_value" -v after="$after_value" 'BEGIN {exit !(after == before)}' ||
          die "$name changed during the exact product round trip"
      fi
    done
  done
}

build_product_reference_index() {
  local ndjson="${PRIVATE_DIR}/product-refs.ndjson" output="${PRIVATE_DIR}/product-refs.json"
  local file path
  : >"$ndjson"
  while IFS= read -r file; do
    path="${file#${ARTIFACT_DIR}/}"
    [[ "$path" != "$file" && -f "$file" && ! -L "$file" ]] || die "unsafe product artifact while indexing refs: $file"
    jq -nc --arg path "$path" --arg sha "sha256:$(sha256_file "$file")" \
      '{key:$path,value:{path:$path,sha256:$sha}}' >>"$ndjson"
  done < <(find "${ARTIFACT_DIR}/product" -type f -print | LC_ALL=C sort)
  jq -s 'from_entries' "$ndjson" >"$output"
}

build_clickhouse_isolation_artifact() {
  local typed="${ARTIFACT_DIR}/product/clickhouse-isolation.json"
  local sql='SELECT tenant_id, trace_id, span_id, name, service, toUnixTimestamp64Nano(start) AS start_time_unix_nano FROM default.probectl_otel_spans FINAL WHERE trace_id IN ({trace_a:String}, {trace_b:String}) ORDER BY tenant_id, trace_id FORMAT JSONEachRow'
  local a_path b_path unset_path
  jq -n --arg schema 'probectl.delivery-audit-clickhouse-isolation/v1' --arg sql "$sql" \
    --arg trace_a "$PRODUCT_TRACE_MARKER_A" --arg trace_b "$PRODUCT_TRACE_MARKER_B" \
    --slurpfile stores "${PRIVATE_DIR}/product-stores.json" '
      ($stores[0].clickhouse_isolation) as $ch |
      {schema:$schema,user:"probectl",database:"default",table:"probectl_otel_spans",tenant_setting:"SQL_probectl_tenant",
       sql:$sql,parameters:{trace_a:$trace_a,trace_b:$trace_b},tenant_a:$ch.tenant_a,tenant_b:$ch.tenant_b,
       tenant_a_observed_at:$ch.tenant_a_observed_at,tenant_b_observed_at:$ch.tenant_b_observed_at,
       unset_observed_at:$ch.unset_observed_at,
       tenant_a_response:{path:$ch.tenant_a_response,sha256:""},
       tenant_b_response:{path:$ch.tenant_b_response,sha256:""},
       unset_response:{path:$ch.unset_response,sha256:""}}
    ' >"${PRIVATE_DIR}/clickhouse-isolation.unhashed.json"
  a_path="$(jq -er .tenant_a_response.path "${PRIVATE_DIR}/clickhouse-isolation.unhashed.json")"
  b_path="$(jq -er .tenant_b_response.path "${PRIVATE_DIR}/clickhouse-isolation.unhashed.json")"
  unset_path="$(jq -er .unset_response.path "${PRIVATE_DIR}/clickhouse-isolation.unhashed.json")"
  jq \
    --arg a_sha "sha256:$(sha256_file "${ARTIFACT_DIR}/${a_path}")" \
    --arg b_sha "sha256:$(sha256_file "${ARTIFACT_DIR}/${b_path}")" \
    --arg unset_sha "sha256:$(sha256_file "${ARTIFACT_DIR}/${unset_path}")" \
    '.tenant_a_response.sha256=$a_sha | .tenant_b_response.sha256=$b_sha | .unset_response.sha256=$unset_sha' \
    "${PRIVATE_DIR}/clickhouse-isolation.unhashed.json" >"$typed"
  jq -e '
    .schema=="probectl.delivery-audit-clickhouse-isolation/v1" and .user=="probectl" and
    .database=="default" and .table=="probectl_otel_spans" and .tenant_setting=="SQL_probectl_tenant" and
    all(.tenant_a_response,.tenant_b_response,.unset_response; (.sha256|test("^sha256:[0-9a-f]{64}$")))
  ' "$typed" >/dev/null || die "typed product ClickHouse isolation artifact is malformed"
  chmod 0644 "$typed"
}

build_product_pipeline_manifest() {
  local refs="${PRIVATE_DIR}/product-refs.json"
  local clickhouse_sql='SELECT tenant_id, trace_id, span_id, name, service, toUnixTimestamp64Nano(start) AS start_time_unix_nano FROM default.probectl_otel_spans FINAL WHERE trace_id = {trace:String} FORMAT JSONEachRow'
  build_product_reference_index
  jq -n \
    --arg schema 'probectl.delivery-audit-product-pipeline/v1' \
    --arg receipt_id "$PRODUCT_RECEIPT_ID" --arg source_git_sha "$AUDIT_GIT_SHA" --arg source_tree_sha "$AUDIT_TREE_SHA" \
    --arg started_at "$PRODUCT_STARTED_AT" --arg completed_at "$PRODUCT_COMPLETED_AT" \
    --arg counter_before_at "$PRODUCT_COUNTER_BEFORE_OBSERVED_AT" --arg counter_after_at "$PRODUCT_COUNTER_AFTER_OBSERVED_AT" \
    --arg tenant_a "$TENANT_A" --arg tenant_b "$TENANT_B" \
    --arg metric_a "$PRODUCT_METRIC_MARKER_A" --arg metric_b "$PRODUCT_METRIC_MARKER_B" \
    --arg trace_a "$PRODUCT_TRACE_MARKER_A" --arg trace_b "$PRODUCT_TRACE_MARKER_B" \
    --arg span_a "$PRODUCT_TRACE_SPAN_ID_A" --arg span_b "$PRODUCT_TRACE_SPAN_ID_B" \
    --arg clickhouse_sql "$clickhouse_sql" \
    --slurpfile refs "$refs" \
    --slurpfile ingest "${PRIVATE_DIR}/product-ingest.json" \
    --slurpfile kafka "${PRIVATE_DIR}/product-kafka.json" \
    --slurpfile stores "${PRIVATE_DIR}/product-stores.json" \
    --slurpfile query_times "${PRIVATE_DIR}/product-query-times.json" \
    --slurpfile stack "${ARTIFACT_DIR}/stack-inventory.json" '
      def ref($path): $refs[0][$path];
      def ingest_for($tenant): $ingest[0].tenants[] | select(.tenant==$tenant);
      def kafka_for($signal;$tenant): $kafka[0][$signal][] | select(.tenant==$tenant);
      def store_for($tenant): $stores[0].tenants[] | select(.tenant==$tenant);
      def query_time($tenant;$label): $query_times[0][] | select(.tenant==$tenant and .label==$label) | .observed_at;
      def metric_selector($marker): "probectl_otlp_completeness_product_marker{marker=\"\($marker)\"}";
      def direct_metric_selector($tenant;$marker): "probectl_otlp_completeness_product_marker{marker=\"\($marker)\",tenant_id=\"\($tenant)\"}";
      def metric_control($tenant;$label;$marker):
        (metric_selector($marker)) as $selector |
        {observed_at:query_time($tenant;$label),command:("probectl metric query --query query="+$selector),method:"GET",
         path:("/v1/grafana/api/v1/query?query="+($selector|@uri)),
         api_observation:ref("product/\($tenant)/\($label)-api.json")};
      def trace_control($tenant;$label;$trace):
        {observed_at:query_time($tenant;$label),command:("probectl otlp traces --query trace_id="+$trace),method:"GET",
         path:("/v1/otlp/traces?trace_id="+$trace),
         api_observation:ref("product/\($tenant)/\($label)-api.json")};
      def tenant_pipeline($tenant;$metric;$metric_value;$trace;$span):
        (ingest_for($tenant)) as $ing |
        (kafka_for("metrics";$tenant)) as $km |
        (kafka_for("traces";$tenant)) as $kt |
        (store_for($tenant)) as $store |
        (direct_metric_selector($tenant;$metric)) as $direct_selector |
        {tenant:$tenant,
         metrics:{correlation_id:$metric,service_name:("completeness-"+$metric),
           metric_name:"completeness_product_marker",stored_metric_name:"probectl_otlp_completeness_product_marker",value:$metric_value,
           time_unix_nano:$ing.metrics.time_unix_nano,
           ingest:{observed_at:$ing.metrics.observed_at,url:"https://control:4318/v1/metrics",auth_mode:"tenant_otlp_bearer",method:"POST",status:$ing.metrics.status,
             request:ref($ing.metrics.request_path),response:ref($ing.metrics.response_path)},
           kafka:{topic:$km.topic,partition:$km.partition,offset:$km.offset,key:ref($km.key_path),payload:ref($km.payload_path),group_offset:ref($km.group_offset_path)},
           control_query:metric_control($tenant;"metrics-control-own";$metric),
           prometheus_direct:{observed_at:$store.prometheus_observed_at,user:"audit",url:("https://prometheus:9090/api/v1/query?query="+($direct_selector|@uri)),query:$direct_selector,response:ref($store.prometheus_response)}},
         traces:{correlation_id:$trace,trace_id:$trace,span_id:$span,service_name:("completeness-"+$trace),span_name:"completeness-product-marker",
           start_time_unix_nano:$ing.traces.start_time_unix_nano,end_time_unix_nano:$ing.traces.end_time_unix_nano,
           ingest:{observed_at:$ing.traces.observed_at,url:"https://control:4318/v1/traces",auth_mode:"tenant_otlp_bearer",method:"POST",status:$ing.traces.status,
             request:ref($ing.traces.request_path),response:ref($ing.traces.response_path)},
           kafka:{topic:$kt.topic,partition:$kt.partition,offset:$kt.offset,key:ref($kt.key_path),payload:ref($kt.payload_path),group_offset:ref($kt.group_offset_path)},
           control_query:trace_control($tenant;"traces-control-own";$trace),
           clickhouse_direct:{observed_at:$store.clickhouse_observed_at,user:"probectl",database:"default",table:"probectl_otel_spans",tenant_setting:"SQL_probectl_tenant",
             tenant_setting_value:$tenant,sql:$clickhouse_sql,parameters:{trace:$trace},response:ref($store.clickhouse_response)}}};
      (tenant_pipeline($tenant_a;$metric_a;84001;$trace_a;$span_a)) as $a |
      (tenant_pipeline($tenant_b;$metric_b;84002;$trace_b;$span_b)) as $b |
      {schema:$schema,receipt_id:$receipt_id,source_git_sha:$source_git_sha,source_tree_sha:$source_tree_sha,
       control_image_id:$stack[0].release.control.image_id,cli_sha256:$stack[0].release.cli.sha256,
       started_at:$started_at,completed_at:$completed_at,tenants:[
        ($a + {foreign_queries:{metrics:metric_control($tenant_a;"metrics-control-foreign";$metric_b),traces:trace_control($tenant_a;"traces-control-foreign";$trace_b)}}),
        ($b + {foreign_queries:{metrics:metric_control($tenant_b;"metrics-control-foreign";$metric_a),traces:trace_control($tenant_b;"traces-control-foreign";$trace_a)}})
      ],integrity:{before_observed_at:$counter_before_at,after_observed_at:$counter_after_at,
          before:ref("product/pipeline-counters-before.prom"),after:ref("product/pipeline-counters-after.prom")},
        clickhouse_isolation:ref("product/clickhouse-isolation.json")}
    ' >"${ARTIFACT_DIR}/product-pipeline.json"
  jq -e --arg a "$TENANT_A" --arg b "$TENANT_B" '
    .schema=="probectl.delivery-audit-product-pipeline/v1" and (.tenants|length)==2 and
    ([.tenants[].tenant]|sort)==([$a,$b]|sort) and
    all(.tenants[]; (.metrics.ingest.request.sha256|test("^sha256:[0-9a-f]{64}$")) and
      (.metrics.kafka.group_offset.sha256|test("^sha256:[0-9a-f]{64}$")) and
      (.traces.clickhouse_direct.response.sha256|test("^sha256:[0-9a-f]{64}$")))
  ' "${ARTIFACT_DIR}/product-pipeline.json" >/dev/null || die "assembled product pipeline manifest is malformed"
  chmod 0644 "${ARTIFACT_DIR}/product-pipeline.json"
}

run_product_pipeline() {
  local token_a="$1" token_b="$2" otlp_token_a otlp_token_b human_path_id
  log "exercising two-tenant OTLP -> Kafka -> Prometheus/ClickHouse release-product round trips"
  generate_product_markers
  human_path_id="$(jq -er .human_path.id "${ARTIFACT_DIR}/capability-manifest.json")"
  require_safe_id human_path_id "$human_path_id"
  PRODUCT_RECEIPT_ID="${AUDIT_ITEM}-${AUDIT_CAPABILITY_ID}-${human_path_id}-${AUDIT_GIT_SHA:0:12}-$(date -u +%Y%m%dT%H%M%SZ)"
  require_safe_id product_receipt_id "$PRODUCT_RECEIPT_ID"
  PRODUCT_STARTED_AT="$(utc_now)"
  install -d -m 0755 "${ARTIFACT_DIR}/product"
  capture_pipeline_counters "${ARTIFACT_DIR}/product/pipeline-counters-before.prom"
  PRODUCT_COUNTER_BEFORE_OBSERVED_AT="$(utc_now)"
  otlp_token_a="$(mint_otlp_token "$TENANT_A" "$token_a" a)"
  otlp_token_b="$(mint_otlp_token "$TENANT_B" "$token_b" b)"
  run_product_ingest_probe "$otlp_token_a" "$otlp_token_b"
  unset otlp_token_a otlp_token_b
  run_product_kafka_probe
  capture_product_queries "$token_a" "$token_b"
  jq -s . "${PRIVATE_DIR}/product-query-times.ndjson" >"${PRIVATE_DIR}/product-query-times.json"
  run_product_store_probe
  capture_product_group_offsets
  capture_pipeline_counters "${ARTIFACT_DIR}/product/pipeline-counters-after.prom"
  PRODUCT_COUNTER_AFTER_OBSERVED_AT="$(utc_now)"
  validate_product_counter_deltas
  build_clickhouse_isolation_artifact
  PRODUCT_COMPLETED_AT="$(utc_now)"
  build_product_pipeline_manifest
}

cli_expect_failure() {
  local tenant="$1" token="$2" output="$3"
  shift 3
  set +e
  PROBECTL_API_TOKEN="$token" PROBECTL_TENANT="$tenant" \
    compose --profile tools run --rm -T -e PROBECTL_API_TOKEN -e PROBECTL_TENANT cli --json "$@" \
    >"$output" 2>&1
  local status=$?
  set -e
  [[ "$status" -ne 0 ]] || die "expected foreign-tenant CLI lookup to fail"
  # API errors contain no credentials, but cap retained text defensively.
  head -c 4096 "$output" > "${output}.bounded"
  mv "${output}.bounded" "$output"
  [[ -s "$output" ]] || die "foreign-tenant CLI failure produced no bounded diagnostic"
  CLI_FAILURE_EXIT_CODE="$status"
}

capture_foreign_denial() {
  local tenant="$1" target_tenant="$2" token="$3" foreign_id="$4" label="$5"
  local api_raw="${PRIVATE_DIR}/${label}-api.json" cli_raw="${PRIVATE_DIR}/${label}-cli.txt"
  local api_artifact="${ARTIFACT_DIR}/api-denial-${label}.json"
  local cli_artifact="${ARTIFACT_DIR}/cli-denial-${label}.txt"
  local meta="${PRIVATE_DIR}/denial-${label}-meta.json" status api_code
  [[ "$foreign_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
    die "foreign test ID is not a lowercase UUID"
  require_safe_id denial_label "$label"
  status="$(
    PROBECTL_API_TOKEN="$token" PROBECTL_TENANT="$tenant" \
      compose --profile tools run --rm -T --no-deps \
        -e PROBECTL_API_TOKEN -e PROBECTL_TENANT --user 0 --entrypoint /bin/bash http-probe \
        -ec '
          set -euo pipefail
          foreign_id="$1"
          label="$2"
          case "$foreign_id" in (*[!0-9a-f-]*) exit 64 ;; esac
          case "$label" in (*[!A-Za-z0-9._-]*) exit 64 ;; esac
          exec curl --cacert /audit/pki/ca.crt --silent --show-error \
            --output "/audit/private/${label}-api.json" --write-out "%{http_code}" \
            --header "Accept: application/json" \
            --header "Authorization: Bearer ${PROBECTL_API_TOKEN}" \
            --header "X-Probectl-Tenant: ${PROBECTL_TENANT}" \
            "https://control:8443/v1/tests/${foreign_id}"
        ' -- "$foreign_id" "$label"
  )"
  [[ "$status" =~ ^(401|403|404)$ ]] || die "foreign-object API status=$status, want 401, 403, or 404"
  [[ -s "$api_raw" && ! -L "$api_raw" ]] || die "foreign-object API response was not retained"
  api_code="$(jq -er '.error.code | select(type=="string" and length>0)' "$api_raw")" ||
    die "foreign-object API response has no structured error code"

  CLI_FAILURE_EXIT_CODE=0
  cli_expect_failure "$tenant" "$token" "$cli_raw" test get "$foreign_id"
  (( CLI_FAILURE_EXIT_CODE != 0 )) || die "foreign-object CLI unexpectedly exited zero"
  rg -F "(${api_code}" "$cli_raw" >/dev/null ||
    die "release CLI failure did not match authenticated API error code $api_code"
  if rg -F "$token" "$api_raw" "$cli_raw" >/dev/null; then
    die "foreign-object evidence unexpectedly contains its bearer token"
  fi

  jq -n \
    --arg schema 'probectl.delivery-audit-api-observation/v1' \
    --arg tenant "$tenant" --arg target "$target_tenant" \
    --arg command "probectl test get $foreign_id" --arg path "/v1/tests/$foreign_id" \
    --arg api_code "$api_code" --argjson status "$status" --slurpfile body "$api_raw" \
    '{schema:$schema,redacted:true,auth_mode:"tenant_mcp_bearer",tenant:$tenant,target_tenant:$target,command:$command,method:"GET",path:$path,status:$status,error_code:$api_code,body:$body[0]}' \
    >"$api_artifact"
  install -m 0644 "$cli_raw" "$cli_artifact"
  jq -n --argjson status "$status" --argjson exit_code "$CLI_FAILURE_EXIT_CODE" \
    '{status:$status,cli_exit_status:$exit_code}' >"$meta"
  chmod 0644 "$api_artifact"
}

write_success_api_observation() {
  local tenant="$1" command="$2" method="$3" path="$4" cli_output="$5" output="$6"
  jq -n --arg tenant "$tenant" --arg command "$command" --arg method "$method" --arg path "$path" \
    --slurpfile body "$cli_output" \
    '{schema:"probectl.delivery-audit-api-observation/v1",redacted:true,auth_mode:"tenant_mcp_bearer",tenant:$tenant,command:$command,method:$method,path:$path,status:200,body:$body[0]}' \
    >"$output"
  chmod 0644 "$output"
}

run_f50_capability() {
  local token_a="$1" token_b="$2"
  local create_a="${PRIVATE_DIR}/create-a.json" create_b="${PRIVATE_DIR}/create-b.json"
  local list_a="${PRIVATE_DIR}/list-a.json" list_b="${PRIVATE_DIR}/list-b.json"
  local isolation_a="${ARTIFACT_DIR}/isolation-a.json" isolation_b="${ARTIFACT_DIR}/isolation-b.json"
  local isolation_api_a="${ARTIFACT_DIR}/isolation-a-api.json" isolation_api_b="${ARTIFACT_DIR}/isolation-b-api.json"
  cli_json "$TENANT_A" "$token_a" isolation status >"$isolation_a"
  cli_json "$TENANT_B" "$token_b" isolation status >"$isolation_b"
  jq -e --arg tenant "$TENANT_A" '.tenant_id==$tenant and .rls.healthy==true and .rls.enforced==true and .silo_routing.fail_closed==true' "$isolation_a" >/dev/null ||
    die "tenant A isolation posture was not healthy and fail-closed"
  jq -e --arg tenant "$TENANT_B" '.tenant_id==$tenant and .rls.healthy==true and .rls.enforced==true and .silo_routing.fail_closed==true' "$isolation_b" >/dev/null ||
    die "tenant B isolation posture was not healthy and fail-closed"
  if rg -F "$TENANT_B" "$isolation_a" >/dev/null || rg -F "$TENANT_A" "$isolation_b" >/dev/null; then
    die "isolation status leaked the foreign tenant identifier"
  fi
  write_success_api_observation "$TENANT_A" "probectl isolation status" "GET" "/v1/isolation/status" "$isolation_a" "$isolation_api_a"
  write_success_api_observation "$TENANT_B" "probectl isolation status" "GET" "/v1/isolation/status" "$isolation_b" "$isolation_api_b"
  cli_json "$TENANT_A" "$token_a" test create --name "$AUDIT_TEST_A_NAME" --type tcp --target example.invalid:443 --interval 60 >"$create_a"
  cli_json "$TENANT_B" "$token_b" test create --name "$AUDIT_TEST_B_NAME" --type tcp --target example.invalid:443 --interval 60 >"$create_b"
  cli_json "$TENANT_A" "$token_a" test list >"$list_a"
  cli_json "$TENANT_B" "$token_b" test list >"$list_b"
  local id_a id_b
  id_a="$(jq -er .id "$create_a")"
  id_b="$(jq -er .id "$create_b")"
  jq -e --arg own "$AUDIT_TEST_A_NAME" --arg foreign "$AUDIT_TEST_B_NAME" \
    'any(.[]; .name==$own) and (all(.[]; .name!=$foreign))' "$list_a" >/dev/null || die "tenant A list isolation failed"
  jq -e --arg own "$AUDIT_TEST_B_NAME" --arg foreign "$AUDIT_TEST_A_NAME" \
    'any(.[]; .name==$own) and (all(.[]; .name!=$foreign))' "$list_b" >/dev/null || die "tenant B list isolation failed"
  capture_foreign_denial "$TENANT_A" "$TENANT_B" "$token_a" "$id_b" 'a-to-b'
  capture_foreign_denial "$TENANT_B" "$TENANT_A" "$token_b" "$id_a" 'b-to-a'
  local denial_api_a="${ARTIFACT_DIR}/api-denial-a-to-b.json" denial_api_b="${ARTIFACT_DIR}/api-denial-b-to-a.json"
  local denial_cli_a="${ARTIFACT_DIR}/cli-denial-a-to-b.txt" denial_cli_b="${ARTIFACT_DIR}/cli-denial-b-to-a.txt"
  local denial_meta_a="${PRIVATE_DIR}/denial-a-to-b-meta.json" denial_meta_b="${PRIVATE_DIR}/denial-b-to-a-meta.json"

  jq -n --arg ta "$TENANT_A" --arg tb "$TENANT_B" --arg id_a "$id_a" --arg id_b "$id_b" \
    --arg cli_sha_a "sha256:$(sha256_file "$isolation_a")" --arg cli_sha_b "sha256:$(sha256_file "$isolation_b")" \
    --arg api_sha_a "sha256:$(sha256_file "$isolation_api_a")" --arg api_sha_b "sha256:$(sha256_file "$isolation_api_b")" \
    --arg denial_cli_sha_a "sha256:$(sha256_file "$denial_cli_a")" --arg denial_cli_sha_b "sha256:$(sha256_file "$denial_cli_b")" \
    --arg denial_api_sha_a "sha256:$(sha256_file "$denial_api_a")" --arg denial_api_sha_b "sha256:$(sha256_file "$denial_api_b")" \
    --argjson denial_a_status "$(jq -r .status "$denial_meta_a")" --argjson denial_b_status "$(jq -r .status "$denial_meta_b")" \
    --argjson denial_a_exit "$(jq -r .cli_exit_status "$denial_meta_a")" --argjson denial_b_exit "$(jq -r .cli_exit_status "$denial_meta_b")" \
    '{schema:"probectl.delivery-audit-cli-transcript/v1",redacted:true,observations:[
      {auth_mode:"tenant_mcp_bearer",tenant:$ta,command:"probectl isolation status",method:"GET",path:"/v1/isolation/status",expected:"success",cli_exit_status:0,cli_output_artifact:"isolation-a.json",cli_output_sha256:$cli_sha_a,response_artifact:"isolation-a-api.json",status_provenance:"cli_structured_response",status:200,success:true,expectation_met:true,response_sha256:$api_sha_a},
      {auth_mode:"tenant_mcp_bearer",tenant:$tb,command:"probectl isolation status",method:"GET",path:"/v1/isolation/status",expected:"success",cli_exit_status:0,cli_output_artifact:"isolation-b.json",cli_output_sha256:$cli_sha_b,response_artifact:"isolation-b-api.json",status_provenance:"cli_structured_response",status:200,success:true,expectation_met:true,response_sha256:$api_sha_b},
      {auth_mode:"tenant_mcp_bearer",tenant:$ta,target_tenant:$tb,command:("probectl test get "+$id_b),method:"GET",path:("/v1/tests/"+$id_b),expected:"rejected",cli_exit_status:$denial_a_exit,cli_output_artifact:"cli-denial-a-to-b.txt",cli_output_sha256:$denial_cli_sha_a,response_artifact:"api-denial-a-to-b.json",status_provenance:"same_auth_https_companion",companion_request_artifact:"api-denial-a-to-b.json",companion_request_sha256:$denial_api_sha_a,status:$denial_a_status,success:false,expectation_met:true,response_sha256:$denial_api_sha_a},
      {auth_mode:"tenant_mcp_bearer",tenant:$tb,target_tenant:$ta,command:("probectl test get "+$id_a),method:"GET",path:("/v1/tests/"+$id_a),expected:"rejected",cli_exit_status:$denial_b_exit,cli_output_artifact:"cli-denial-b-to-a.txt",cli_output_sha256:$denial_cli_sha_b,response_artifact:"api-denial-b-to-a.json",status_provenance:"same_auth_https_companion",companion_request_artifact:"api-denial-b-to-a.json",companion_request_sha256:$denial_api_sha_b,status:$denial_b_status,success:false,expectation_met:true,response_sha256:$denial_api_sha_b}
    ]}' \
    > "${ARTIFACT_DIR}/cli-transcript.json"

  jq -n \
    --arg proof_kind 'postgres_bidirectional_rls_query_isolation' \
    --arg a "$TENANT_A" --arg b "$TENANT_B" \
    --arg own_a "$AUDIT_TEST_A_NAME" --arg own_b "$AUDIT_TEST_B_NAME" \
    --slurpfile la "$list_a" --slurpfile lb "$list_b" \
    '{proof_kind:$proof_kind,tenant_a:$a,tenant_b:$b,seeded_tenant_a_rows:1,seeded_tenant_b_rows:1,tenant_a_own_visible_rows:([$la[0][]|select(.name==$own_a)]|length),tenant_b_own_visible_rows:([$lb[0][]|select(.name==$own_b)]|length),tenant_a_to_b_visible_rows:([$la[0][]|select(.name==$own_b)]|length),tenant_b_to_a_visible_rows:([$lb[0][]|select(.name==$own_a)]|length),detail:"release CLI create/list plus foreign-id GET refusal traversed control and FORCE-RLS Postgres in both directions"}' \
    > "${PRIVATE_DIR}/postgres-proof.json"

  jq -n --arg item "$AUDIT_ITEM" --arg capability "$AUDIT_CAPABILITY_ID" \
    --arg ta "$TENANT_A" --arg tb "$TENANT_B" \
    --arg own_a "$AUDIT_TEST_A_NAME" --arg own_b "$AUDIT_TEST_B_NAME" \
    '{schema:"probectl.completeness-audit-capability/v1",item:$item,capability_id:$capability,
      scope:{mode:"tenant_plane",browser_auth_mode:"tenant_oidc",cli_auth_mode:"tenant_mcp_bearer",provider_compatibility_validated:false,capability_driver:{kind:"builtin",runtime_path:"scripts/run_completeness_audit.sh#run_f50_capability"},browser_driver:{kind:"builtin",runtime_path:"scripts/completeness_audit_browser.mjs"}},
      human_path:{id:"f50-tenant-oidc-isolation",path_class:"executable_end_user",coverage:"one_governed_end_user_path",summary:"Tenant admin checks pooled isolation, then verifies each tenant sees only its own target through the release CLI and real-Dex UI."},
      binary:{entrypoint:"cmd/probectl-control/builders.go#func verifyServePosture",default_build_command:"go build ./cmd/probectl-control"},api:{operation_id:"getIsolationStatus",method:"GET",path:"/v1/isolation/status"},browser_api:{operation_id:"listTests",method:"GET",path:"/v1/tests",required_get_paths:["/v1/lifecycle/retention","/v1/tests"]},cli:{primary_operation:"probectl isolation status",commands:["probectl isolation status"]},ui:{primary_route:"/admin",observations:[{tenant:$ta,tenant_name:"Completeness Audit A",product_path:"/ui/admin",route:"/admin",heading:{role:"heading",name:"Admin & Settings"},content_scope:"#main-content",own_text:"pooled",foreign_text:"Completeness Audit B",screenshot:"tenant-a-admin.png"},{tenant:$tb,tenant_name:"Completeness Audit B",product_path:"/ui/admin",route:"/admin",heading:{role:"heading",name:"Admin & Settings"},content_scope:"#main-content",own_text:"pooled",foreign_text:"Completeness Audit A",screenshot:"tenant-b-admin.png"},{tenant:$ta,tenant_name:"Completeness Audit A",product_path:"/ui/targets",route:"/targets",heading:{role:"heading",name:"Targets & Tests"},content_scope:"#main-content",own_text:$own_a,foreign_text:$own_b,screenshot:"tenant-a-targets.png"},{tenant:$tb,tenant_name:"Completeness Audit B",product_path:"/ui/targets",route:"/targets",heading:{role:"heading",name:"Targets & Tests"},content_scope:"#main-content",own_text:$own_b,foreign_text:$own_a,screenshot:"tenant-b-targets.png"}]},docs_path:"docs/isolation.md#Tenant isolation models",activation:{enabled_by_default:true,runtime_active:true,enable_cli_command:"",enable_ui_route:"",license_tier:"core",license_state:"not_applicable",build_tags:[]},summary:"F50 tenancy and hard isolation: startup posture, tenant-scoped isolation status, bidirectional Postgres RLS, and real-Dex /admin isolation visibility plus /targets observations"}' \
    > "${ARTIFACT_DIR}/capability-manifest.json"
}

validate_capability_manifest() {
  local manifest="${ARTIFACT_DIR}/capability-manifest.json"
  local authority="${AUDIT_SOURCE_DIR}/${AUDIT_AUTHORITY_REL}"
  local custom=false
  [[ -n "$AUDIT_CAPABILITY_DRIVER_PATH" ]] && custom=true
  [[ -s "$manifest" && ! -L "$manifest" ]] || die "capability driver did not produce capability-manifest.json"
  [[ -f "$authority" && ! -L "$authority" ]] || die "exact-tree delivery-audit authority registry is missing"
  jq -e --arg item "$AUDIT_ITEM" --arg capability "$AUDIT_CAPABILITY_ID" --argjson custom "$custom" \
    --slurpfile stack "${ARTIFACT_DIR}/stack-inventory.json" --slurpfile authority "$authority" '
    (keys|sort)==(["activation","api","binary","browser_api","capability_id","cli","docs_path","human_path","item","schema","scope","summary","ui"]|sort) and
    .schema=="probectl.completeness-audit-capability/v1" and .item==$item and .capability_id==$capability and
    (.scope|keys|sort)==(["browser_auth_mode","browser_driver","capability_driver","cli_auth_mode","mode","provider_compatibility_validated"]|sort) and
    .scope==$stack[0].harness and
    ((.scope.mode=="tenant_plane" and .scope.browser_auth_mode=="tenant_oidc" and .scope.cli_auth_mode=="tenant_mcp_bearer" and .scope.provider_compatibility_validated==false and (.api.path|startswith("/v1/")) and (.browser_api.path|startswith("/v1/"))) or
     false) and
    (.human_path|keys|sort)==(["coverage","id","path_class","summary"]|sort) and
    (.human_path.id|test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and
    .human_path.path_class=="executable_end_user" and .human_path.coverage=="one_governed_end_user_path" and
    (.human_path.summary|type)=="string" and (.human_path.summary|length)>0 and
    (.binary|keys|sort)==(["default_build_command","entrypoint"]|sort) and (.binary.entrypoint|test("^cmd/.+\\.go#.+$")) and (.binary.default_build_command|startswith("go build ")) and
    (.api|keys|sort)==(["method","operation_id","path"]|sort) and
    (.api.operation_id|type)=="string" and (.api.method|IN("GET","POST","PUT","PATCH","DELETE")) and (.api.method=="GET" or $custom) and
    (.browser_api|keys|sort)==(["method","operation_id","path","required_get_paths"]|sort) and
    (.browser_api.operation_id|type)=="string" and .browser_api.method=="GET" and
    (.browser_api.required_get_paths|type)=="array" and (.browser_api.required_get_paths|length)>0 and
    all(.browser_api.required_get_paths[]; startswith("/v1/")) and
    (.browser_api.path as $browser_path | (.browser_api.required_get_paths|index($browser_path))!=null) and
    (.cli|keys|sort)==(["commands","primary_operation"]|sort) and (.cli.commands|type)=="array" and (.cli.commands|length)>0 and all(.cli.commands[]; type=="string" and startswith("probectl ")) and (.cli.primary_operation as $primary_cli | (.cli.commands|index($primary_cli))!=null) and
    (.ui|keys|sort)==(["observations","primary_route"]|sort) and (.ui.primary_route|startswith("/")) and (.ui.observations|type)=="array" and (.ui.observations|length)>=2 and (.ui.observations|length)<=16 and
    all(.ui.observations[];
      (keys|sort)==(["content_scope","foreign_text","heading","own_text","product_path","route","screenshot","tenant","tenant_name"]|sort) and
      (.heading|keys|sort)==(["name","role"]|sort) and .heading.role=="heading" and
      .content_scope=="#main-content" and (.tenant|type)=="string" and (.tenant_name|type)=="string" and (.tenant_name|length)>0 and (.product_path|startswith("/ui/")) and (.route|startswith("/")) and
      (.own_text|type)=="string" and (.own_text|length)>0 and (.foreign_text|type)=="string" and (.foreign_text|length)>0 and .own_text!=.foreign_text and
      (.screenshot|test("^[A-Za-z0-9._-]+\\.png$"))) and
    ([.ui.observations[].tenant]|unique|length)==2 and
    ([.ui.observations[].screenshot]|unique|length)==(.ui.observations|length) and
    (.ui.primary_route as $primary_route | ([.ui.observations[].route]|index($primary_route))!=null) and
    (.docs_path|test("^docs/[A-Za-z0-9_./-]+\\.md(#[^\\n]+)?$")) and (.summary|type)=="string" and (.summary|length)>0 and
    (.activation|keys|sort)==(["build_tags","enable_cli_command","enable_ui_route","enabled_by_default","license_state","license_tier","runtime_active"]|sort) and
    (.activation.enabled_by_default|type)=="boolean" and .activation.runtime_active==true and
    (.activation.enable_cli_command|type)=="string" and (.activation.enable_ui_route|type)=="string" and
    .activation.license_tier=="core" and .activation.license_state=="not_applicable" and (.activation.build_tags|type)=="array" and
    $authority[0].schema=="probectl.delivery-audit-authority/v1" and ($authority[0].executable_protocols|type)=="array"
  ' "$manifest" >/dev/null || die "capability manifest does not satisfy probectl.completeness-audit-capability/v1"
  jq -e --arg item "$AUDIT_ITEM" --arg capability "$AUDIT_CAPABILITY_ID" --slurpfile manifest "$manifest" '
    .schema=="probectl.delivery-audit-authority/v1" and
    ([.executable_protocols[] | select(.item==$item and .capability_id==$capability and .human_path_id==$manifest[0].human_path.id and .mode==$manifest[0].scope.mode)]|length)==1
  ' "$authority" >/dev/null || die "item/capability/human-path/mode is not uniquely authorized by the exact-tree delivery-audit registry"
  [[ "$(jq -r .scope.mode "$manifest")" == "tenant_plane" ]] ||
    die "provider_plane is a governed extension boundary and is non-promotable until a fixed provider_session browser harness plus legitimate offline Provider license inputs are implemented"
}

run_capability() {
  local token_a="$1" token_b="$2"
  if [[ -n "$AUDIT_CAPABILITY_DRIVER_PATH" ]]; then
    [[ -x "$AUDIT_CAPABILITY_DRIVER_PATH" && "sha256:$(sha256_file "$AUDIT_CAPABILITY_DRIVER_PATH")" == "$AUDIT_CAPABILITY_DRIVER_SHA256" ]] ||
      die "frozen capability driver changed after prepare"
    AUDIT_TOKEN_A_FILE="${PRIVATE_DIR}/token-a" AUDIT_TOKEN_B_FILE="${PRIVATE_DIR}/token-b" \
      "$AUDIT_CAPABILITY_DRIVER_PATH" "$STATE_DIR"
    [[ -s "${ARTIFACT_DIR}/cli-transcript.json" && -s "${PRIVATE_DIR}/postgres-proof.json" ]] ||
      die "custom capability driver did not produce the documented evidence contract"
  else
    [[ "$AUDIT_CAPABILITY_ID" == "F50" ]] || die "capability $AUDIT_CAPABILITY_ID needs a frozen custom driver"
    run_f50_capability "$token_a" "$token_b"
  fi
  validate_capability_manifest
}

kafka_probe() {
  local topic="probectl.completeness.events.${AUDIT_GIT_SHA:0:12}" raw="${PRIVATE_DIR}/kafka-messages.txt"
  compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9093 \
    --command-config /etc/kafka/secrets/client.properties --create --if-not-exists --topic "$topic" --partitions 1 --replication-factor 1 >/dev/null
  {
    printf '%s:{"tenant_id":"%s","marker":"a"}\n' "$TENANT_A" "$TENANT_A"
    printf '%s:{"tenant_id":"%s","marker":"b"}\n' "$TENANT_B" "$TENANT_B"
  } | compose exec -T kafka /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server kafka:9093 \
      --producer.config /etc/kafka/secrets/client.properties --topic "$topic" \
      --property parse.key=true --property key.separator=: >/dev/null
  compose exec -T kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server kafka:9093 \
    --consumer.config /etc/kafka/secrets/client.properties --topic "$topic" --from-beginning --max-messages 2 \
    --property print.key=true --property key.separator=: >"$raw"
  local seen_a=0 seen_b=0 missing=0 mismatch=0 key payload tenant
  while IFS=: read -r key payload; do
    [[ -n "$key" && -n "$payload" ]] || { missing=$((missing+1)); continue; }
    tenant="$(jq -er .tenant_id <<<"$payload")" || { missing=$((missing+1)); continue; }
    [[ "$tenant" == "$key" ]] || mismatch=$((mismatch+1))
    [[ "$tenant" == "$TENANT_A" ]] && seen_a=$((seen_a+1))
    [[ "$tenant" == "$TENANT_B" ]] && seen_b=$((seen_b+1))
  done <"$raw"
  (( seen_a > 0 && seen_b > 0 && missing == 0 && mismatch == 0 )) || die "Kafka tenant-tag integrity probe failed"
  jq -n --arg proof_kind 'kafka_authenticated_sasl_ssl_tenant_tag_integrity' \
    --arg a "$TENANT_A" --arg b "$TENANT_B" --arg topic "$topic" \
    --argjson oa "$seen_a" --argjson ob "$seen_b" --argjson missing "$missing" --argjson mismatch "$mismatch" \
    '{proof_kind:$proof_kind,security_protocol:"SASL_SSL",authentication_mechanism:"PLAIN",control_configured_for_broker:true,control_connectivity_proven:false,authenticated_manual_tag_probe:true,tls_verified:true,sasl_authenticated:true,tenant_a:$a,tenant_b:$b,observed_tenant_a_messages:$oa,observed_tenant_b_messages:$ob,missing_tenant_tag_messages:$missing,mismatched_tenant_tag_messages:$mismatch,product_emitted_messages_observed:false,observed_product_messages:0,reader_isolation_claimed:false,detail:("release control was configured for the real SASL_SSL broker, but control connectivity not proven because its client is lazy. A separate authenticated manual probe on " + $topic + " preserved both mandatory tenant tags. No product-emitted messages observed; reader isolation is not claimed.")}' \
    > "${PRIVATE_DIR}/kafka-proof.json"
}

store_probes() {
  log "assembling real product-store isolation and tenant-label integrity proofs"
  compose --profile tools run --rm -T store-probe prometheus >"${PRIVATE_DIR}/prometheus-raw.json"
  jq -e '.service=="prometheus" and .passed==true and .seeded_tenant_a_rows==1 and .seeded_tenant_b_rows==1 and .tenant_a_own_visible_rows==1 and .tenant_b_own_visible_rows==1 and .total_observed_series==2 and .expected_tenant_labeled_series==2 and .missing_tenant_label_series==0 and .mismatched_tenant_label_series==0' \
    "${PRIVATE_DIR}/prometheus-raw.json" >/dev/null || die "unfiltered Prometheus label-integrity proof is invalid"

  jq '.clickhouse_isolation | {proof_kind:"clickhouse_product_otel_setting_scoped_reader_isolation",
      product_path_configured:true,control_round_trip_observed:true,database,table,reader_user,tenant_setting,
      reader_policy_observed,tenant_a,tenant_b,seeded_tenant_a_rows,seeded_tenant_b_rows,
      tenant_a_own_visible_rows,tenant_b_own_visible_rows,tenant_a_to_b_visible_rows,tenant_b_to_a_visible_rows,
      unset_visible_rows,detail:"release control stored and read both exact OTLP trace markers through default.probectl_otel_spans; predicate-free direct reads as probectl used SQL_probectl_tenant and proved A-only, B-only, and unset-zero visibility"}' \
    "${PRIVATE_DIR}/product-stores.json" >"${PRIVATE_DIR}/clickhouse-proof.json"
  jq '{proof_kind:"prometheus_authenticated_tls_tenant_label_integrity",product_path_configured:true,control_round_trip_observed:true,direct_query:true,unfiltered_series_query:true,tls_verified:true,authenticated:true,tenant_a,tenant_b,observed_tenant_a_series:.tenant_a_own_visible_rows,observed_tenant_b_series:.tenant_b_own_visible_rows,total_observed_series,expected_tenant_labeled_series,missing_tenant_label_series,mismatched_tenant_label_series,isolation_claimed:false,detail:(.detail + "; release control also round-tripped both exact tenant OTLP marker series through this configured Prometheus, with independent exact direct queries bound in product-pipeline.json")}' \
    "${PRIVATE_DIR}/prometheus-raw.json" >"${PRIVATE_DIR}/prometheus-proof.json"
  jq '.control_connectivity_proven=true | .product_emitted_messages_observed=true | .observed_product_messages=4 |
      .detail += " Release consumers committed beyond four independently observed product OTLP records; typed kafka-consumer-groups provenance is bound in product-pipeline.json."' \
    "${PRIVATE_DIR}/kafka-proof.json" >"${PRIVATE_DIR}/kafka-proof.json.next"
  mv "${PRIVATE_DIR}/kafka-proof.json.next" "${PRIVATE_DIR}/kafka-proof.json"

  jq -n --arg schema 'probectl.delivery-audit-store-probes/v1' \
    --slurpfile postgres "${PRIVATE_DIR}/postgres-proof.json" \
    --slurpfile clickhouse "${PRIVATE_DIR}/clickhouse-proof.json" \
    --slurpfile kafka "${PRIVATE_DIR}/kafka-proof.json" \
    --slurpfile prometheus "${PRIVATE_DIR}/prometheus-proof.json" \
    '{schema:$schema,product_pipeline_artifact:"product-pipeline.json",postgres:$postgres[0],clickhouse:$clickhouse[0],kafka:$kafka[0],prometheus:$prometheus[0],provider_boundary:{}}' \
    >"${ARTIFACT_DIR}/store-probes.json"
}

tool_curl() {
  compose --profile tools run --rm -T --no-deps --entrypoint curl browser "$@"
}

assert_plaintext_http_rejected() {
  local listener="$1" status rc
  shift
  set +e
  status="$(tool_curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "$@" 2>/dev/null)"
  rc=$?
  set -e
  if (( rc != 0 )); then
    [[ "$status" == "000" ]] ||
      die "$listener plaintext probe failed with transport status=$status instead of a closed TLS socket"
    return
  fi
  # Go HTTPS listeners deliberately answer an obvious plaintext request with a
  # protocol-layer 400 before dispatch. That is TLS rejection, not an accepted
  # application request. Any ordinary application status (including 401/404)
  # would prove a plaintext handler exists and must fail the audit.
  [[ "$status" == "400" ]] ||
    die "$listener accepted plaintext with application status=$status"
}

public_leaf_sha256() {
  local certificate="$1" fingerprint
  [[ -f "$certificate" && ! -L "$certificate" ]] || die "expected public leaf is missing or unsafe: $certificate"
  fingerprint="$(openssl x509 -in "$certificate" -outform DER 2>/dev/null |
    openssl dgst -sha256 -r | awk 'NF {print "sha256:" tolower($1); exit}')"
  [[ "$fingerprint" =~ ^sha256:[0-9a-f]{64}$ ]] || die "could not fingerprint expected public leaf: $certificate"
  printf '%s' "$fingerprint"
}

assert_tls_probe_public_only() {
  if ! compose --profile tools run --rm -T --no-deps --entrypoint /bin/bash tls-probe -ec '
    set -Eeuo pipefail
    [[ -r /audit/ca.crt ]]
    openssl x509 -in /audit/ca.crt -noout >/dev/null 2>&1
    forbidden=(
      /audit/pki
      /audit/private
      /audit/control-secrets
      /audit/control-data/pgpass
      /run/secrets/prom-basic-auth.json
      /run/secrets/ch-basic-auth.json
      /etc/kafka/secrets/client.properties
      /etc/kafka/secrets/kafka.keystore.p12
      /etc/kafka/secrets/kafka.truststore.p12
    )
    for path in "${forbidden[@]}"; do
      [[ ! -e "$path" ]]
    done
  '; then
    die "TLS served-leaf probe can access a private path or cannot read its public CA"
  fi
}

capture_served_leaf_sha256() {
  local listener="$1" authority="$2" server_name="$3" certificate_service="$4" starttls="${5:-}"
  local expected observed
  case "$starttls" in
    ""|postgres) ;;
    *) die "unsupported TLS probe STARTTLS mode for $listener: $starttls" ;;
  esac
  expected="$(public_leaf_sha256 "${CERT_DIR}/${certificate_service}/tls.crt")"
  if ! observed="$(compose --profile tools run --rm -T --no-deps \
    -e AUDIT_TLS_AUTHORITY="$authority" -e AUDIT_TLS_SERVER_NAME="$server_name" -e AUDIT_TLS_STARTTLS="$starttls" \
    --entrypoint /bin/bash tls-probe -ec '
      set -Eeuo pipefail
      transcript=/tmp/served-leaf.pem
      starttls_args=()
      case "$AUDIT_TLS_STARTTLS" in
        "") ;;
        postgres) starttls_args=(-starttls postgres) ;;
        *) exit 64 ;;
      esac
      timeout 15 openssl s_client \
        -connect "$AUDIT_TLS_AUTHORITY" \
        -servername "$AUDIT_TLS_SERVER_NAME" \
        -CAfile /audit/ca.crt \
        -verify_hostname "$AUDIT_TLS_SERVER_NAME" \
        -verify_return_error \
        -no_ign_eof \
        -showcerts \
        "${starttls_args[@]}" </dev/null >"$transcript" 2>/dev/null
      digest="$(openssl x509 -in "$transcript" -outform DER 2>/dev/null | openssl dgst -sha256 -r)"
      digest="${digest%% *}"
      [[ "$digest" =~ ^[0-9A-Fa-f]{64}$ ]]
      printf "sha256:%s\n" "${digest,,}"
    ')"; then
    die "$listener did not complete a CA- and hostname-verified TLS handshake at $authority"
  fi
  [[ "$observed" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$listener returned a malformed served-leaf fingerprint"
  [[ "$observed" == "$expected" ]] ||
    die "$listener served leaf $observed, expected $expected from ${certificate_service}/tls.crt"
  printf '%s' "$observed"
}

listener_probes() {
  log "probing trusted TLS, plaintext rejection, and authentication on every listener"
  local control_auth dex_malformed_auth clickhouse_auth prometheus_auth otlp_missing_auth otlp_invalid_auth
  local control_peer otlp_http_peer dex_peer postgres_peer kafka_peer clickhouse_peer prometheus_peer
  assert_tls_probe_public_only
  tool_curl --cacert /audit/pki/ca.crt -fsS https://control:8443/readyz >/dev/null
  control_auth="$(tool_curl --cacert /audit/pki/ca.crt -sS -o /dev/null -w '%{http_code}' https://control:8443/v1/tests)"
  [[ "$control_auth" == "401" ]] || die "control unauthenticated API status=$control_auth, want 401"
  assert_plaintext_http_rejected control http://control:8443/readyz

  otlp_missing_auth="$(tool_curl --cacert /audit/pki/ca.crt -sS -o /dev/null -w '%{http_code}' \
    -X POST -H 'Content-Type: application/x-protobuf' --data-binary '' https://control:4318/v1/metrics)"
  [[ "$otlp_missing_auth" == "401" ]] || die "OTLP/HTTP missing-auth status=$otlp_missing_auth, want 401"
  otlp_invalid_auth="$(tool_curl --cacert /audit/pki/ca.crt -sS -o /dev/null -w '%{http_code}' \
    -X POST -H 'Content-Type: application/x-protobuf' -H 'Authorization: Bearer invalid-audit-token' \
    --data-binary '' https://control:4318/v1/metrics)"
  [[ "$otlp_invalid_auth" == "401" ]] || die "OTLP/HTTP invalid-auth status=$otlp_invalid_auth, want 401"
  assert_plaintext_http_rejected OTLP/HTTP -X POST -H 'Content-Type: application/x-protobuf' --data-binary '' \
    http://control:4318/v1/metrics

  tool_curl --cacert /audit/pki/ca.crt -fsS https://dex:5556/dex/.well-known/openid-configuration >/dev/null
  # /dex/auth is intentionally public and renders the connector chooser. The
  # negative boundary is its continuation endpoint: an invented request handle
  # must not reach a login or token-issuing path.
  dex_malformed_auth="$(tool_curl --cacert /audit/pki/ca.crt -sS -o /dev/null -w '%{http_code}' \
    'https://dex:5556/dex/auth/local?req=invalid')"
  [[ "$dex_malformed_auth" == "404" ]] ||
    die "Dex malformed authorization continuation status=$dex_malformed_auth, want 404"
  assert_plaintext_http_rejected Dex http://dex:5556/dex/.well-known/openid-configuration

  compose exec -T postgres \
    psql "host=postgres port=5432 dbname=probectl user=probectl sslmode=verify-full sslrootcert=/audit/pki/ca.crt" -Atqc \
    "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()" | grep -qx t || die "Postgres verified TLS probe failed"
  set +e
  compose exec -T postgres \
    psql "host=postgres port=5432 dbname=probectl user=probectl sslmode=disable connect_timeout=3" -Atqc 'SELECT 1' >/dev/null 2>&1
  local pg_plain=$?
  compose exec -T -e PGPASSFILE=/dev/null postgres \
    psql -w "host=postgres port=5432 dbname=probectl user=probectl sslmode=verify-full sslrootcert=/audit/pki/ca.crt connect_timeout=3" -Atqc 'SELECT 1' >/dev/null 2>&1
  local pg_unauth=$?
  set -e
  (( pg_plain != 0 && pg_unauth != 0 )) || die "Postgres plaintext/unauthenticated rejection failed"

  compose exec -T kafka /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9093 \
    --command-config /etc/kafka/secrets/client.properties >/dev/null
  set +e
  compose exec -T kafka timeout 8 /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9093 \
    --command-config /etc/kafka/secrets/plaintext.properties >/dev/null 2>&1
  local kafka_plain=$?
  compose exec -T kafka timeout 8 /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:9093 \
    --command-config /etc/kafka/secrets/tls-unauthenticated.properties >/dev/null 2>&1
  local kafka_unauth=$?
  set -e
  (( kafka_plain != 0 && kafka_unauth != 0 )) || die "Kafka plaintext/unauthenticated rejection failed"

  # ClickHouse deliberately exposes `/` and `/ping` as unauthenticated
  # liveness endpoints. Probe an actual SQL request so this proves that an
  # unauthenticated caller cannot read data instead of rejecting public
  # liveness by mistake. The pinned 24.8 server maps AUTHENTICATION_FAILED to
  # HTTP 403.
  clickhouse_auth="$(tool_curl --cacert /audit/pki/ca.crt -sS -o /dev/null -w '%{http_code}' \
    'https://clickhouse:8443/?query=SELECT%201')"
  [[ "$clickhouse_auth" == "403" ]] ||
    die "ClickHouse unauthenticated SQL status=$clickhouse_auth, want 403"
  assert_plaintext_http_rejected ClickHouse http://clickhouse:8443/

  prometheus_auth="$(tool_curl --cacert /audit/pki/ca.crt -sS -o /dev/null -w '%{http_code}' https://prometheus:9090/-/healthy)"
  [[ "$prometheus_auth" == "401" ]] || die "Prometheus unauthenticated status=$prometheus_auth, want 401"
  assert_plaintext_http_rejected Prometheus http://prometheus:9090/-/healthy

  jq -e '(.sessions|length)>0 and all(.sessions[]; .auth_mode=="tenant_oidc" and .credentialed_login==true)' \
    "${ARTIFACT_DIR}/browser-network.json" >/dev/null || die "Dex credentialed browser login evidence is missing"

  # These are seven distinct, protocol-correct handshakes. Control and OTLP
  # intentionally use the same declared leaf, but are observed independently
  # on their separate sockets. No listener evidence is written until every
  # served DER leaf matches its expected public certificate.
  control_peer="$(capture_served_leaf_sha256 control control:8443 control control)"
  otlp_http_peer="$(capture_served_leaf_sha256 otlp_http control:4318 control control)"
  dex_peer="$(capture_served_leaf_sha256 dex dex:5556 dex dex)"
  postgres_peer="$(capture_served_leaf_sha256 postgres postgres:5432 postgres postgres postgres)"
  kafka_peer="$(capture_served_leaf_sha256 kafka kafka:9093 kafka kafka)"
  clickhouse_peer="$(capture_served_leaf_sha256 clickhouse clickhouse:8443 clickhouse clickhouse)"
  prometheus_peer="$(capture_served_leaf_sha256 prometheus prometheus:9090 prometheus prometheus)"

  jq -n --arg schema 'probectl.delivery-audit-tls-listeners/v1' \
    --arg control_peer "$control_peer" --arg otlp_http_peer "$otlp_http_peer" --arg dex_peer "$dex_peer" \
    --arg postgres_peer "$postgres_peer" --arg kafka_peer "$kafka_peer" \
    --arg clickhouse_peer "$clickhouse_peer" --arg prometheus_peer "$prometheus_peer" \
    '{schema:$schema,listeners:{control:{auth_model:"protected",certificate_service:"control",peer_certificate_sha256:$control_peer,trusted_tls:true,plaintext_rejected:true,unauthenticated_rejected:true},otlp_http:{auth_model:"protected",certificate_service:"control",peer_certificate_sha256:$otlp_http_peer,trusted_tls:true,plaintext_rejected:true,unauthenticated_rejected:true,invalid_authentication_rejected:true},dex:{auth_model:"public_oidc",certificate_service:"dex",peer_certificate_sha256:$dex_peer,trusted_tls:true,plaintext_rejected:true,metadata_public:true,malformed_authorization_rejected:true,real_credentialed_login_succeeded:true},postgres:{auth_model:"protected",certificate_service:"postgres",peer_certificate_sha256:$postgres_peer,trusted_tls:true,plaintext_rejected:true,unauthenticated_rejected:true},kafka:{auth_model:"protected",certificate_service:"kafka",peer_certificate_sha256:$kafka_peer,trusted_tls:true,plaintext_rejected:true,unauthenticated_rejected:true},clickhouse:{auth_model:"protected",certificate_service:"clickhouse",peer_certificate_sha256:$clickhouse_peer,trusted_tls:true,plaintext_rejected:true,unauthenticated_rejected:true},prometheus:{auth_model:"protected",certificate_service:"prometheus",peer_certificate_sha256:$prometheus_peer,trusted_tls:true,plaintext_rejected:true,unauthenticated_rejected:true}}}' \
    >"${PRIVATE_DIR}/listeners.json"
}

browser_probes() {
  if [[ -n "$AUDIT_BROWSER_DRIVER_PATH" ]]; then
    [[ "sha256:$(sha256_file "$AUDIT_BROWSER_DRIVER_PATH")" == "$AUDIT_BROWSER_DRIVER_SHA256" ]] ||
      die "frozen browser driver changed after prepare"
  fi
  log "proving WebKit rejects before CA installation"
  compose --profile tools run --rm -T --no-deps --entrypoint /bin/bash browser -ec \
    'exec node "$AUDIT_BROWSER_SCRIPT" pretrust'
  jq -e '.rejected_without_ca == true and .ignore_https_errors == false and .rejection_class=="certificate_trust" and (.diagnostic|type)=="string" and (.diagnostic|length)>0' "${ARTIFACT_DIR}/tls-pretrust.json" >/dev/null ||
    die "pre-trust browser evidence is invalid"
}

runtime_inventory() {
  local modes="${PRIVATE_DIR}/key-modes.txt" kafka_modes="${PRIVATE_DIR}/kafka-key-modes.txt"
  local pgpass_modes="${PRIVATE_DIR}/pgpass-modes.txt"
  local artifact_mode artifact_owner bin_mode bin_owner helper_mode helper_owner credential credential_mode credential_owner
  local store_identity browser_identity http_identity
  artifact_mode="$(stat -f '%Lp' "$ARTIFACT_DIR" 2>/dev/null || stat -c '%a' "$ARTIFACT_DIR")"
  artifact_owner="$(stat -f '%u:%g' "$ARTIFACT_DIR" 2>/dev/null || stat -c '%u:%g' "$ARTIFACT_DIR")"
  bin_mode="$(stat -f '%Lp' "$BIN_DIR" 2>/dev/null || stat -c '%a' "$BIN_DIR")"
  bin_owner="$(stat -f '%u:%g' "$BIN_DIR" 2>/dev/null || stat -c '%u:%g' "$BIN_DIR")"
  helper_mode="$(stat -f '%Lp' "${BIN_DIR}/completeness-store-probe" 2>/dev/null || stat -c '%a' "${BIN_DIR}/completeness-store-probe")"
  helper_owner="$(stat -f '%u:%g' "${BIN_DIR}/completeness-store-probe" 2>/dev/null || stat -c '%u:%g' "${BIN_DIR}/completeness-store-probe")"
  [[ "$artifact_mode" == "770" && "$artifact_owner" == "${AUDIT_HOST_UID}:${AUDIT_HOST_GID}" ]] || die "artifact handoff directory ownership/mode is unsafe"
  [[ "$bin_mode" == "700" && "$bin_owner" == "${AUDIT_HOST_UID}:${AUDIT_HOST_GID}" ]] || die "probe binary directory ownership/mode is unsafe"
  [[ "$helper_mode" == "500" && "$helper_owner" == "${AUDIT_HOST_UID}:${AUDIT_HOST_GID}" ]] || die "probe binary ownership/mode is unsafe"
  for credential in "${PRIVATE_DIR}/prom-probe-basic-auth.json" "${PRIVATE_DIR}/ch-probe-basic-auth.json"; do
    credential_mode="$(stat -f '%Lp' "$credential" 2>/dev/null || stat -c '%a' "$credential")"
    credential_owner="$(stat -f '%u:%g' "$credential" 2>/dev/null || stat -c '%u:%g' "$credential")"
    [[ "$credential_mode" == "600" && "$credential_owner" == "${AUDIT_HOST_UID}:${AUDIT_HOST_GID}" ]] ||
      die "probe credential ownership/mode is unsafe"
  done
  store_identity="$(compose --profile tools run --rm -T --no-deps store-probe identity)"
  browser_identity="$(compose --profile tools run --rm -T --no-deps --entrypoint node browser \
    --eval 'process.stdout.write(JSON.stringify({uid:process.geteuid(),gid:process.getegid()}))')"
  http_identity="$(compose --profile tools run --rm -T --no-deps --entrypoint node http-probe \
    --eval 'process.stdout.write(JSON.stringify({uid:process.geteuid(),gid:process.getegid()}))')"
  jq -e -s --argjson uid "$AUDIT_HOST_UID" --argjson gid "$AUDIT_HOST_GID" \
    'length == 1 and .[0] == {uid:$uid,gid:$gid}' <<<"$store_identity" >/dev/null ||
    die "store probe effective UID/GID does not match the prepared ownership model"
  jq -e -s --argjson uid 0 --argjson gid "$AUDIT_HOST_GID" \
    'length == 1 and .[0] == {uid:$uid,gid:$gid}' <<<"$browser_identity" >/dev/null ||
    die "browser probe effective UID/GID does not match the prepared ownership model"
  jq -e -s --argjson uid "$AUDIT_HOST_UID" --argjson gid "$AUDIT_HOST_GID" \
    'length == 1 and .[0] == {uid:$uid,gid:$gid}' <<<"$http_identity" >/dev/null ||
    die "HTTP probe effective UID/GID does not match the prepared ownership model"
  compose exec -T postgres stat -c '%n %u:%g %a' \
    /audit/pki/control/tls.key /audit/pki/dex/tls.key /audit/pki/postgres/tls.key \
    /audit/pki/kafka/tls.key /audit/pki/clickhouse/tls.key /audit/pki/prometheus/tls.key \
    /audit/pki/prometheus/web.yml >"$modes"
  awk '$3 != "600" { exit 1 }' "$modes" || die "one or more runtime key/config files is not mode 0600"
  awk '
    /control\/tls.key|dex\/tls.key/ {if ($2!="65532:65532") exit 1}
    /postgres\/tls.key/ {if ($2!="999:999") exit 1}
    /kafka\/tls.key/ {if ($2!="0:0") exit 1}
    /clickhouse\/tls.key/ {if ($2!="101:101") exit 1}
    /prometheus\/tls.key|prometheus\/web.yml/ {if ($2!="65534:65534") exit 1}
  ' "$modes" || die "one or more runtime key/config owners is unexpected"
  compose exec -T kafka stat -c '%n %u:%g %a' \
    /etc/kafka/secrets/kafka.keystore.p12 /etc/kafka/secrets/kafka.truststore.p12 \
    /etc/kafka/secrets/keystore_creds /etc/kafka/secrets/key_creds \
    /etc/kafka/secrets/truststore_creds /etc/kafka/secrets/client.properties >"$kafka_modes"
  awk '$2 != "1000:1000" || $3 != "600" { exit 1 }' "$kafka_modes" ||
    die "Kafka consumed key/config files are not UID 1000 mode 0600"
  compose run --rm -T --no-deps --entrypoint stat pki-init -c '%n %u:%g %a' \
    /audit/control-data/pgpass /audit/pki/postgres/pgpass \
    /audit/control-secrets/prom-basic-auth.json /audit/control-secrets/ch-basic-auth.json \
    /audit/pki/clickhouse/scope-client.xml >"$pgpass_modes"
  awk '
    /control-data\/pgpass/ {if ($2!="65532:65532" || $3!="600") exit 1; control=1}
    /postgres\/pgpass/ {if ($2!="999:999" || $3!="600") exit 1; postgres=1}
    /control-secrets\/prom-basic-auth.json/ {if ($2!="65532:65532" || $3!="600") exit 1; prom=1}
    /control-secrets\/ch-basic-auth.json/ {if ($2!="65532:65532" || $3!="600") exit 1; ch=1}
    /clickhouse\/scope-client.xml/ {if ($2!="101:101" || $3!="600") exit 1; scope=1}
    END {if (!control || !postgres || !prom || !ch || !scope) exit 1}
  ' "$pgpass_modes" || die "control datastore credential files are not owner-only mode 0600"
  jq '
      .runtime = {tls_private_key_files:{control:{path:"/audit/pki/control/tls.key",uid:65532,gid:65532,mode:"0600",consumed_by:"control",purpose:"server_tls_private_key"},dex:{path:"/audit/pki/dex/tls.key",uid:65532,gid:65532,mode:"0600",consumed_by:"dex",purpose:"server_tls_private_key"},postgres:{path:"/audit/pki/postgres/tls.key",uid:999,gid:999,mode:"0600",consumed_by:"postgres",purpose:"server_tls_private_key"},kafka:{path:"/etc/kafka/secrets/kafka.keystore.p12",uid:1000,gid:1000,mode:"0600",consumed_by:"kafka",purpose:"server_tls_private_key"},clickhouse:{path:"/audit/pki/clickhouse/tls.key",uid:101,gid:101,mode:"0600",consumed_by:"clickhouse",purpose:"server_tls_private_key"},prometheus:{path:"/audit/pki/prometheus/tls.key",uid:65534,gid:65534,mode:"0600",consumed_by:"prometheus",purpose:"server_tls_private_key"}}} |
      .services |= with_entries(.value.running=true)
    ' \
    "${ARTIFACT_DIR}/stack-inventory.json" >"${ARTIFACT_DIR}/stack-inventory.json.next"
  mv "${ARTIFACT_DIR}/stack-inventory.json.next" "${ARTIFACT_DIR}/stack-inventory.json"
}

copy_public_certificate_evidence() {
  local target="${ARTIFACT_DIR}/certificates" service
  [[ ! -e "$target" ]] || die "refusing to reuse public certificate artifact directory"
  install -d -m 0755 "$target"
  install -m 0644 "${CERT_DIR}/manifest.json" "${target}/manifest.json"
  install -m 0644 "${CERT_DIR}/ca.crt" "${target}/ca.crt"
  for service in control dex postgres kafka clickhouse prometheus; do
    install -d -m 0755 "${target}/${service}"
    install -m 0644 "${CERT_DIR}/${service}/tls.crt" "${target}/${service}/tls.crt"
  done
  if find "$target" -type f ! -name '*.crt' ! -name 'manifest.json' -print -quit | grep -q .; then
    die "public certificate evidence contains an unexpected file"
  fi
  if rg -n 'PRIVATE KEY' "$target" >/dev/null; then
    die "private key material reached the public certificate evidence"
  fi
}

run_audit() {
  need docker
  need node
  load_state
  assert_exact_clean_source
  assert_frozen_harness
  assert_frozen_drivers
  STACK_ACTIVE=1
  trap cleanup_run_exit EXIT INT TERM
  log "starting isolated internal-only project ${AUDIT_COMPOSE_PROJECT}"
  compose up -d --wait
  tool_curl --cacert /audit/pki/ca.crt --retry 30 --retry-all-errors --retry-delay 1 -fsS https://control:8443/readyz >/dev/null

  browser_probes
  seed_two_tenants
  local token_a token_b
  token_a="$(mint_token "$TENANT_A" "$USER_A")"
  token_b="$(mint_token "$TENANT_B" "$USER_B")"
  printf '%s' "$token_a" >"${PRIVATE_DIR}/token-a"
  printf '%s' "$token_b" >"${PRIVATE_DIR}/token-b"
  chmod 0600 "${PRIVATE_DIR}/token-a" "${PRIVATE_DIR}/token-b"

  run_capability "$token_a" "$token_b"
  run_product_pipeline "$token_a" "$token_b"
  # Browser sessions run after the exact tests and role bindings exist.
  compose --profile tools run --rm -T --no-deps --entrypoint /bin/bash browser -ec \
    'install -m 0644 /audit/pki/ca.crt /usr/local/share/ca-certificates/probectl-completeness-audit.crt; update-ca-certificates >/dev/null; exec node "$AUDIT_BROWSER_SCRIPT" journey'
  jq -e --slurpfile manifest "${ARTIFACT_DIR}/capability-manifest.json" '
    .live_https==true and .request_interception==false and .ignore_https_errors==false and
    (.sessions|length)==($manifest[0].ui.observations|length) and
    all(.sessions[]; .rendered==true and .tenant_indicator_visible==true and .expected_evidence_visible==true and .foreign_evidence_absent==true and (.screenshot|type)=="string")
  ' "${ARTIFACT_DIR}/browser-network.json" >/dev/null || die "trusted browser evidence is invalid"
  kafka_probe
  store_probes
  listener_probes
  runtime_inventory
  copy_public_certificate_evidence

  local ca_fingerprint
  ca_fingerprint="sha256:$(openssl x509 -in "${CERT_DIR}/ca.crt" -outform DER | openssl dgst -sha256 -r | awk '{print $1}')"
  jq -n --arg schema 'probectl.delivery-audit-tls-trust/v1' \
    --arg fingerprint "$ca_fingerprint" \
    --arg not_before "$(jq -r .valid_from "${CERT_DIR}/manifest.json")" \
    --arg not_after "$(jq -r .expires_at "${CERT_DIR}/manifest.json")" \
    --slurpfile listener "${PRIVATE_DIR}/listeners.json" --slurpfile pre "${ARTIFACT_DIR}/tls-pretrust.json" \
    '{schema:$schema,ca_fingerprint:$fingerprint,ca_not_before:$not_before,ca_not_after:$not_after,browser_rejected_without_ca:$pre[0].rejected_without_ca,browser_trusted_with_ca:true,browser_pretrust_failure:{browser:$pre[0].browser,url:"https://control:8443/readyz",error_class:"unknown_authority",sanitized_message:$pre[0].diagnostic,rejected:$pre[0].rejected_without_ca},ignore_https_errors:false,listeners:$listener[0].listeners,certificate_manifest:"certificates/manifest.json",ca_certificate:"certificates/ca.crt",service_certificates:{clickhouse:"certificates/clickhouse/tls.crt",control:"certificates/control/tls.crt",dex:"certificates/dex/tls.crt",kafka:"certificates/kafka/tls.crt",postgres:"certificates/postgres/tls.crt",prometheus:"certificates/prometheus/tls.crt"}}' \
    >"${ARTIFACT_DIR}/tls-trust.json"

  jq -n \
    --arg git_sha "$AUDIT_GIT_SHA" --arg tree_sha "$AUDIT_TREE_SHA" --arg capability "$AUDIT_CAPABILITY_ID" \
    --arg registry_sha "sha256:$(sha256_file "${AUDIT_SOURCE_DIR}/capabilities.yaml")" \
    --slurpfile manifest "${ARTIFACT_DIR}/capability-manifest.json" \
    '{schema:"probectl.delivery-audit-static-reachability/v1",source_git_sha:$git_sha,source_tree_sha:$tree_sha,capability_id:$capability,registry_path:"capabilities.yaml",registry_sha256:$registry_sha,static_gate:"internal/completeness.Validator",validator_passed:true,binary_entrypoint:$manifest[0].binary.entrypoint,default_build_command:$manifest[0].binary.default_build_command,default_build_reachable:true,api:$manifest[0].api,cli_operation:$manifest[0].cli.primary_operation,ui_route:$manifest[0].ui.primary_route,docs_path:$manifest[0].docs_path,observed_in_release:true}' \
    >"${ARTIFACT_DIR}/reachability.json"
  jq '.activation as $activation | $activation + {schema:"probectl.delivery-audit-activation/v1",release_go_tags:$activation.build_tags,dev_auth:false}' \
    "${ARTIFACT_DIR}/capability-manifest.json" >"${ARTIFACT_DIR}/activation.json"

  if [[ "$AUDIT_CAPABILITY_ID" == "F50" ]]; then
    install -m 0644 "${PRIVATE_DIR}/list-a.json" "${ARTIFACT_DIR}/postgres-tenant-a-list.json"
    install -m 0644 "${PRIVATE_DIR}/list-b.json" "${ARTIFACT_DIR}/postgres-tenant-b-list.json"
  fi
  install -m 0644 "${PRIVATE_DIR}/prometheus-raw.json" "${ARTIFACT_DIR}/prometheus-raw.json"

  cleanup_stack
  trap - EXIT INT TERM
  remove_bearer_tokens
  log "real-stack evidence complete: $ARTIFACT_DIR"
}

build_artifact_declarations() {
  local output="$1" ndjson="${PRIVATE_DIR}/artifact-declarations.ndjson" path name kind
  if find "$ARTIFACT_DIR" -type l -print -quit | grep -q .; then
    die "artifact directory contains a symlink"
  fi
  : >"$ndjson"
  while IFS= read -r path; do
    name="${path#${ARTIFACT_DIR}/}"
    [[ "$name" != "$path" && "$name" =~ ^[A-Za-z0-9._/-]+$ ]] || die "artifact path is not controlled: $path"
    case "/$name/" in *'/../'*) die "artifact path traverses its root: $name" ;; esac
    case "$name" in
      cli-transcript.json) kind=cli_transcript ;;
      *.png) kind=ui_screenshot ;;
      browser-network.json) kind=browser_network ;;
      store-probes.json) kind=store_probes ;;
      product-pipeline.json) kind=product_pipeline ;;
      product/*/metrics-ingest-request.pb|product/*/traces-ingest-request.pb) kind=otlp_request ;;
      product/*/metrics-ingest-response.pb|product/*/traces-ingest-response.pb) kind=otlp_response ;;
      product/*/metrics-kafka-key.bin|product/*/traces-kafka-key.bin) kind=kafka_key ;;
      product/*/metrics-kafka-payload.pb|product/*/traces-kafka-payload.pb) kind=kafka_payload ;;
      product/*/metrics-kafka-group-offset.json|product/*/traces-kafka-group-offset.json) kind=kafka_group_offset ;;
      product/*/metrics-kafka-group-offset-raw.txt|product/*/traces-kafka-group-offset-raw.txt) kind=kafka_group_offset_raw ;;
      product/clickhouse-isolation.json) kind=clickhouse_isolation ;;
      product/clickhouse-isolation-tenant-a.jsonl|product/clickhouse-isolation-tenant-b.jsonl|product/clickhouse-isolation-unset.jsonl) kind=clickhouse_isolation_raw ;;
      product/*/metrics-prometheus-direct.json|product/*/traces-clickhouse-direct.json) kind=store_observation ;;
      product/*/*-control-*-cli.json) kind=cli_output ;;
      product/*/*-control-*-api.json) kind=api_observation ;;
      product/pipeline-counters-before.prom|product/pipeline-counters-after.prom) kind=pipeline_counters ;;
      tls-trust.json) kind=tls_trust ;;
      stack-inventory.json) kind=stack_inventory ;;
      linter-output.json) kind=linter_output ;;
      reachability.json) kind=static_reachability ;;
      activation.json) kind=activation_proof ;;
      isolation-a.json|isolation-b.json|cli-denial-*.txt) kind=cli_output ;;
      isolation-a-api.json|isolation-b-api.json|api-denial-*.json) kind=api_observation ;;
      certificates/manifest.json) kind=certificate_manifest ;;
      certificates/*.crt) kind=public_certificate ;;
      negative-receipt.json) kind=negative_receipt ;;
      planted-control.json) kind=negative_fixture ;;
      *) kind=other ;;
    esac
    jq -nc --arg path "$name" --arg kind "$kind" '{path:$path,kind:$kind,bytes:0,sha256:""}' >>"$ndjson"
  done < <(find "$ARTIFACT_DIR" -mindepth 1 -type f -print | LC_ALL=C sort)
  jq -s . "$ndjson" >"$output"
}

build_verified_draft() {
  local artifact_declarations="$1" output="$2" completed_at auditor owner receipt_id human_path_id
  completed_at="${AUDIT_RECEIPT_COMPLETED_AT:?receipt completion time must be frozen once for both drafts}"
  auditor="${PROBECTL_AUDIT_AUDITOR:?set an explicit independent auditor identity before seal}"
  owner="${PROBECTL_AUDIT_IMPLEMENTATION_OWNER:?set the explicit implementation-owner identity before seal}"
  require_safe_id PROBECTL_AUDIT_AUDITOR "$auditor"
  require_safe_id PROBECTL_AUDIT_IMPLEMENTATION_OWNER "$owner"
  [[ "$auditor" != "$owner" ]] || die "auditor must be independent from the implementation owner"
  human_path_id="$(jq -er .human_path.id "${ARTIFACT_DIR}/capability-manifest.json")"
  require_safe_id human_path_id "$human_path_id"
  receipt_id="$(jq -er .receipt_id "${ARTIFACT_DIR}/product-pipeline.json")"
  require_safe_id receipt_id "$receipt_id"

  jq -n \
    --arg receipt_id "$receipt_id" --arg item "$AUDIT_ITEM" --arg capability "$AUDIT_CAPABILITY_ID" \
    --arg started "$AUDIT_STARTED_AT" --arg completed "$completed_at" --arg auditor "$auditor" --arg owner "$owner" \
    --slurpfile manifest "${ARTIFACT_DIR}/capability-manifest.json" \
    --slurpfile stack "${ARTIFACT_DIR}/stack-inventory.json" \
    --slurpfile cli "${ARTIFACT_DIR}/cli-transcript.json" \
    --slurpfile browser "${ARTIFACT_DIR}/browser-network.json" \
    --slurpfile reach "${ARTIFACT_DIR}/reachability.json" \
    --slurpfile activation "${ARTIFACT_DIR}/activation.json" \
    --slurpfile stores "${ARTIFACT_DIR}/store-probes.json" \
    --slurpfile tls "${ARTIFACT_DIR}/tls-trust.json" \
    --slurpfile artifacts "$artifact_declarations" '
    {schema:"probectl.delivery-audit-receipt/v1",receipt_id:$receipt_id,item:$item,capability_id:$capability,status:"VERIFIED",started_at:$started,completed_at:$completed,
     source:$stack[0].source,
     build:{control_commit:$stack[0].source.git_sha,cli_commit:$stack[0].source.git_sha,control_image_id:$stack[0].release.control.image_id,cli_sha256:$stack[0].release.cli.sha256,dev_auth:false,placeholder_ui:false},
     auditor:{agent:$auditor,implementation_owner:$owner,independent_from_implementation:true},
     harness_scope:$manifest[0].scope,
     human_path:($manifest[0].human_path + {reproduced_as_human_path:true}),
     cli:{transcript:"cli-transcript.json",commands:$manifest[0].cli.commands},
     ui:{screenshots:([$manifest[0].ui.observations[].screenshot]|unique),routes:([$manifest[0].ui.observations[].route]|unique)},
     browser_network:{artifact:"browser-network.json",requests:$browser[0].requests,live_https:$browser[0].live_https,request_interception:$browser[0].request_interception},
     reachability:{artifact:"reachability.json",binary_entrypoint:$reach[0].binary_entrypoint,default_build_command:$reach[0].default_build_command,default_build_reachable:$reach[0].default_build_reachable,api:$reach[0].api,cli_operation:$reach[0].cli_operation,ui_route:$reach[0].ui_route,docs_path:$reach[0].docs_path},
     activation:{artifact:"activation.json",enabled_by_default:$activation[0].enabled_by_default,runtime_active:$activation[0].runtime_active,enable_cli_command:$activation[0].enable_cli_command,enable_ui_route:$activation[0].enable_ui_route,docs_path:$activation[0].docs_path,license_tier:$activation[0].license_tier,license_state:$activation[0].license_state,build_tags:$activation[0].build_tags},
     stores:{artifact:"store-probes.json",product_pipeline_artifact:$stores[0].product_pipeline_artifact,postgres:$stores[0].postgres,clickhouse:$stores[0].clickhouse,kafka:$stores[0].kafka,prometheus:$stores[0].prometheus,provider_boundary:$stores[0].provider_boundary},
     tls:{artifact:"tls-trust.json",ca_fingerprint:$tls[0].ca_fingerprint,ca_not_before:$tls[0].ca_not_before,ca_not_after:$tls[0].ca_not_after,browser_rejected_without_ca:$tls[0].browser_rejected_without_ca,browser_trusted_with_ca:$tls[0].browser_trusted_with_ca,browser_pretrust_failure:$tls[0].browser_pretrust_failure,ignore_https_errors:$tls[0].ignore_https_errors,listeners:$tls[0].listeners,certificate_manifest:$tls[0].certificate_manifest,ca_certificate:$tls[0].ca_certificate,service_certificates:$tls[0].service_certificates},
     evidence_sources:{fixture:false,mock:false,testdata:false},artifacts:$artifacts[0]}
  ' >"$output"
}

seal_receipts() {
  need jq
  need node
  load_state
  assert_exact_clean_source
  assert_frozen_harness
  assert_frozen_drivers
  local tool="${BIN_DIR}/probectl-delivery-audit" signing_key declarations base_draft failed_root tenant signal product_required
  local failed_draft failed_receipt failed_lint_raw failed_lint_status verified_draft verified_receipt candidate_lint_status
  [[ -x "$tool" && ! -L "$tool" ]] || die "missing frozen delivery-audit binary"
  for required in capability-manifest.json cli-transcript.json browser-network.json store-probes.json product-pipeline.json \
    product/pipeline-counters-before.prom product/pipeline-counters-after.prom tls-trust.json stack-inventory.json reachability.json activation.json tls-pretrust.json \
    product/clickhouse-isolation.json product/clickhouse-isolation-tenant-a.jsonl product/clickhouse-isolation-tenant-b.jsonl product/clickhouse-isolation-unset.jsonl \
    certificates/manifest.json certificates/ca.crt certificates/control/tls.crt certificates/dex/tls.crt certificates/postgres/tls.crt certificates/kafka/tls.crt certificates/clickhouse/tls.crt certificates/prometheus/tls.crt; do
    [[ -f "${ARTIFACT_DIR}/${required}" && ! -L "${ARTIFACT_DIR}/${required}" ]] || die "missing run artifact: $required"
  done
  for tenant in "$TENANT_A" "$TENANT_B"; do
    for product_required in \
      metrics-ingest-request.pb metrics-ingest-response.pb traces-ingest-request.pb traces-ingest-response.pb \
      metrics-prometheus-direct.json traces-clickhouse-direct.json \
      metrics-control-own-cli.json metrics-control-own-api.json traces-control-own-cli.json traces-control-own-api.json \
      metrics-control-foreign-cli.json metrics-control-foreign-api.json traces-control-foreign-cli.json traces-control-foreign-api.json; do
      [[ -f "${ARTIFACT_DIR}/product/${tenant}/${product_required}" && ! -L "${ARTIFACT_DIR}/product/${tenant}/${product_required}" ]] ||
        die "missing product run artifact: product/${tenant}/${product_required}"
    done
    for signal in metrics traces; do
      for product_required in "${signal}-kafka-key.bin" "${signal}-kafka-payload.pb" \
        "${signal}-kafka-group-offset.json" "${signal}-kafka-group-offset-raw.txt"; do
        [[ -f "${ARTIFACT_DIR}/product/${tenant}/${product_required}" && ! -L "${ARTIFACT_DIR}/product/${tenant}/${product_required}" ]] ||
          die "missing product run artifact: product/${tenant}/${product_required}"
      done
    done
  done
  signing_key="${PROBECTL_AUDIT_SIGNING_KEY:-${PRIVATE_DIR}/receipt-signing.pem}"
  require_safe_path "$signing_key"
  AUDIT_RECEIPT_COMPLETED_AT="$(utc_now)"

  declarations="${PRIVATE_DIR}/artifact-declarations.json"
  base_draft="${PRIVATE_DIR}/receipt-base.json"
  build_artifact_declarations "$declarations"
  build_verified_draft "$declarations" "$base_draft"

  failed_root="${PRIVATE_DIR}/failed-artifacts"
  [[ ! -e "$failed_root" ]] || die "refusing to reuse failed-control artifact directory"
  mkdir -m 0700 "$failed_root"
  printf '%s\n' '{"schema":"probectl.delivery-audit-negative-control/v1","fixture-only":"planted negative control"}' >"${failed_root}/planted-control.json"
  chmod 0600 "${failed_root}/planted-control.json"
  failed_draft="${PRIVATE_DIR}/receipt-failed-draft.json"
  jq '.receipt_id += "-failed" | .status="FAILED" | .evidence_sources.fixture=true | .failure_reasons=["planted fixture evidence must never promote"] | .artifacts=[{path:"planted-control.json",kind:"negative_fixture",bytes:0,sha256:""}]' \
    "$base_draft" >"$failed_draft"
  failed_receipt="${STATE_DIR}/receipt-failed.json"
  "$tool" seal --draft "$failed_draft" --artifacts "$failed_root" --key "$signing_key" --out "$failed_receipt" \
    >"${STATE_DIR}/seal-failed.json"

  failed_lint_raw="${PRIVATE_DIR}/failed-lint-raw.json"
  set +e
  "$tool" lint --receipt "$failed_receipt" --artifacts "$failed_root" >"$failed_lint_raw"
  failed_lint_status=$?
  set -e
  [[ "$failed_lint_status" -ne 0 ]] || die "planted fixture-only receipt unexpectedly passed the linter"
  jq -e '([.diagnostics[].code]|index("fixture-only"))!=null and ([.diagnostics[].code]|index("status-failed"))!=null' \
    "$failed_lint_raw" >/dev/null || die "negative control did not produce fixture-only and status-failed diagnostics"
  install -m 0644 "$failed_receipt" "${ARTIFACT_DIR}/negative-receipt.json"
  install -m 0644 "${failed_root}/planted-control.json" "${ARTIFACT_DIR}/planted-control.json"
  jq -n \
    --arg failed_path 'negative-receipt.json' --arg failed_sha "sha256:$(sha256_file "${ARTIFACT_DIR}/negative-receipt.json")" \
    --arg planted_path 'planted-control.json' --arg planted_sha "sha256:$(sha256_file "${ARTIFACT_DIR}/planted-control.json")" \
    --slurpfile result "$failed_lint_raw" \
    '{schema:"probectl.delivery-audit-linter-output/v1",rejected:true,failed_envelope_path:$failed_path,failed_envelope_sha256:$failed_sha,planted_artifact_path:$planted_path,planted_artifact_sha256:$planted_sha,diagnostics:([$result[0].diagnostics[]|select(.code=="fixture-only" or .code=="status-failed")]|unique_by(.code))}' \
    >"${ARTIFACT_DIR}/linter-output.json"
  jq -e '(.diagnostics|length)==2 and ([.diagnostics[].code]|sort)==["fixture-only","status-failed"]' \
    "${ARTIFACT_DIR}/linter-output.json" >/dev/null || die "strict negative-control report did not retain exactly the required linter diagnostics"

  build_artifact_declarations "$declarations"
  verified_draft="${PRIVATE_DIR}/receipt-verified-draft.json"
  build_verified_draft "$declarations" "$verified_draft"
  verified_receipt="${STATE_DIR}/receipt-verified.json"
  "$tool" seal --draft "$verified_draft" --artifacts "$ARTIFACT_DIR" --source-root "$AUDIT_SOURCE_DIR" \
    --key "$signing_key" --out "$verified_receipt" >"${STATE_DIR}/seal-verified.json"
  jq -er .signer_fingerprint "${STATE_DIR}/seal-verified.json" >"${STATE_DIR}/signer-fingerprint.txt"
  chmod 0644 "$failed_receipt" "$verified_receipt" "${STATE_DIR}/signer-fingerprint.txt"
  set +e
  "$tool" lint --receipt "$verified_receipt" --artifacts "$ARTIFACT_DIR" --source-root "$AUDIT_SOURCE_DIR" \
    >"${STATE_DIR}/lint-candidate.json"
  candidate_lint_status=$?
  set -e
  if (( candidate_lint_status != 0 )); then
    log "candidate receipt is signed but explicitly NON-PROMOTABLE; inspect ${STATE_DIR}/lint-candidate.json"
    return 1
  fi
  log "sealed lint-clean VERIFIED and planted FAILED receipts; signer fingerprint is informational only and is never auto-trusted"
}

purge_runtime_secrets() {
  [[ "$CERT_DIR" == "${STATE_DIR}/certs" && "$RUNTIME_DIR" == "${STATE_DIR}/runtime" && "$PRIVATE_DIR" == "${STATE_DIR}/private" ]] ||
    die "refusing unsafe runtime-secret cleanup"
  # The current certificate generator keeps the CA signer memory-only. Delete
  # every persisted leaf key and defensively remove a future ca.key if one ever
  # appears; public certificates/manifests remain as recomputable evidence.
  find "$CERT_DIR" -type f \( -name 'tls.key' -o -name 'ca.key' \) -delete
  remove_bearer_tokens
  rm -f "${RUNTIME_DIR}/prometheus-web.yml" "$ENV_FILE" \
    "${PRIVATE_DIR}/prom-probe-basic-auth.json" "${PRIVATE_DIR}/ch-probe-basic-auth.json"
  if [[ -z "${PROBECTL_AUDIT_SIGNING_KEY:-}" ]]; then
    rm -f "${PRIVATE_DIR}/receipt-signing.pem"
  fi
  unset POSTGRES_PASSWORD KAFKA_STORE_PASSWORD KAFKA_SASL_PASSWORD CLICKHOUSE_PASSWORD
  unset PROMETHEUS_PASSWORD
  unset DEX_CLIENT_SECRET DEX_AUDIT_PASSWORD DEX_AUDIT_PASSWORD_HASH PROBECTL_SESSION_HMAC_KEY
}

cleanup_prepared_state() {
  need docker
  load_state
  STACK_ACTIVE=1
  cleanup_stack
  purge_runtime_secrets
  log "prepared stack and transient credentials removed; public evidence and non-secret bounded raw observations were retained"
}

verify_receipts() {
  need jq
  load_state
  assert_exact_clean_source
  assert_frozen_harness
  assert_frozen_drivers
  local tool="${BIN_DIR}/probectl-delivery-audit" verified="${STATE_DIR}/receipt-verified.json"
  local failed="${STATE_DIR}/receipt-failed.json" failed_root="${PRIVATE_DIR}/failed-artifacts"
  local fingerprint trusted_key trusted_fingerprint
  [[ -f "$verified" && -f "$failed" ]] || die "sealed receipts are missing"

  "$tool" verify --receipt "$verified" --artifacts "$ARTIFACT_DIR" >"${STATE_DIR}/verify-signature.json"
  jq -e '.cryptographic_status=="SIGNATURE_VALID_UNTRUSTED" and .receipt_status=="VERIFIED"' \
    "${STATE_DIR}/verify-signature.json" >/dev/null || die "untrusted-but-valid signature status was not explicit"
  "$tool" verify --receipt "$failed" --artifacts "$failed_root" >"${STATE_DIR}/verify-failed-signature.json"
  jq -e '.receipt_status=="FAILED"' "${STATE_DIR}/verify-failed-signature.json" >/dev/null || die "FAILED receipt signature verification failed"
  "$tool" lint --receipt "$verified" --artifacts "$ARTIFACT_DIR" --source-root "$AUDIT_SOURCE_DIR" >"${STATE_DIR}/lint-verified.json"
  jq -e '(.diagnostics|length)==0' "${STATE_DIR}/lint-verified.json" >/dev/null || die "VERIFIED receipt semantic lint failed"

  fingerprint="$(jq -er .signer_fingerprint "${STATE_DIR}/seal-verified.json")"
  trusted_key="${PROBECTL_AUDIT_TRUSTED_PUBLIC_KEY:-}"
  trusted_fingerprint="${PROBECTL_AUDIT_TRUSTED_FINGERPRINT:-}"
  if [[ -n "$trusted_key" || -n "$trusted_fingerprint" ]]; then
    local trust_args=()
    if [[ -n "$trusted_key" ]]; then
      require_safe_path "$trusted_key"
      trust_args+=(--trusted-public-key "$trusted_key")
    fi
    if [[ -n "$trusted_fingerprint" ]]; then
      [[ "$trusted_fingerprint" =~ ^sha256:[0-9a-f]{64}$ ]] || die "trusted fingerprint must be an out-of-band sha256 digest"
      trust_args+=(--trusted-fingerprint "$trusted_fingerprint")
    fi
    "$tool" verify --receipt "$verified" --artifacts "$ARTIFACT_DIR" --require-current --repo "$REPO_ROOT" \
      "${trust_args[@]}" >"${STATE_DIR}/verify-current-trusted.json"
    jq -e '.promotion_status=="VERIFIED_CURRENT" and .cryptographic_status=="SIGNATURE_VALID_TRUSTED"' \
      "${STATE_DIR}/verify-current-trusted.json" >/dev/null || die "out-of-band trusted current-SHA verification failed"
  else
    log "signature is valid but non-promotable without an out-of-band trusted key/fingerprint (signer: $fingerprint)"
  fi
  purge_runtime_secrets
  log "verification complete; runtime passwords, TLS leaf keys, bearer tokens, and any state-local signing key were removed"
}

case "$PHASE" in
  prepare) prepare ;;
  run) run_audit ;;
  seal) seal_receipts ;;
  verify) verify_receipts ;;
  cleanup) cleanup_prepared_state ;;
  all)
    prepare
    run_audit
    seal_receipts
    verify_receipts
    ;;
esac
