#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# compose_env_preflight.sh — DPR-007: validate deploy/compose/.env BEFORE the
# production Compose stack starts, so a value the docs told the operator to
# generate cannot turn into a crash-looping control plane with a misleading
# startup error. Checks are structural only; no value is printed.
#
#   compose_env_preflight.sh            validate the .env (PROBECTL_COMPOSE_ENV_FILE overrides the path)
#   compose_env_preflight.sh SELFTEST   prove each planted failure is caught
#
# Rules (each one mirrors a real first-boot failure):
#   POSTGRES_PASSWORD          required; URL-safe only ([A-Za-z0-9._~-]) because
#                              probectl.yml splices it raw into PROBECTL_DATABASE_URL
#   PROBECTL_SESSION_HMAC_KEY  required; exactly 64 hex chars (openssl rand -hex 32)
#   PROBECTL_ENVELOPE_KEY      empty (generated on first boot) or base64 of 32 bytes
#   PROBECTL_TLS_HOSTS         must not be blank when set (the cert would have no SANs)
#   PROBECTL_AUTH_MODE         "session" or "dev"; session without PROBECTL_OIDC_ISSUER
#                              is a WARNING (an overlay such as dex-demo.yml may set it)
#   PROBECTL_LICENSE_PATH      when set, must name a readable file
#   PROBECTL_TLS_DIR           when set, must be a directory holding tls.crt + tls.key
set -euo pipefail

ROOT="${PROBECTL_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ENV_FILE="${PROBECTL_COMPOSE_ENV_FILE:-$ROOT/deploy/compose/.env}"

trim() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  printf '%s' "$v"
}

env_value() { # env_value <file> <key> — first uncommented assignment, quotes stripped
  local file="$1" key="$2" line value
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    case "$line" in
      "$key"=*)
        value="${line#*=}"
        value="$(trim "$value")"
        value="${value%\"}"; value="${value#\"}"
        value="${value%\'}"; value="${value#\'}"
        printf '%s\n' "$value"
        return 0
        ;;
    esac
  done <"$file"
}

check_env() { # check_env <file> -> 0 ok, 2 on any failure; messages on stderr
  local file="$1" fail=0 v
  if [ ! -f "$file" ]; then
    echo "compose env preflight: $file is missing — cp deploy/compose/.env.example deploy/compose/.env and fill it in" >&2
    return 2
  fi

  v="$(env_value "$file" POSTGRES_PASSWORD)"
  if [ -z "$v" ]; then
    echo "compose env preflight: POSTGRES_PASSWORD is empty (openssl rand -hex 24)" >&2; fail=1
  elif ! printf '%s' "$v" | grep -Eq '^[A-Za-z0-9._~-]+$'; then
    echo "compose env preflight: POSTGRES_PASSWORD contains characters that are not URL-safe; it is spliced into PROBECTL_DATABASE_URL, so a '/', '+', '=', '@', ':', '?', '#', '%' or space would make the control plane refuse to start. Use only letters, digits, '.', '_', '~', '-' (openssl rand -hex 24)." >&2; fail=1
  fi

  v="$(env_value "$file" PROBECTL_SESSION_HMAC_KEY)"
  if ! printf '%s' "$v" | grep -Eq '^[0-9a-fA-F]{64}$'; then
    echo "compose env preflight: PROBECTL_SESSION_HMAC_KEY must be exactly 64 hex characters (openssl rand -hex 32)" >&2; fail=1
  fi

  v="$(env_value "$file" PROBECTL_ENVELOPE_KEY)"
  if [ -n "$v" ]; then
    local n
    n="$(printf '%s' "$v" | base64 -d 2>/dev/null | wc -c | tr -d ' ')" || n=0
    if [ "${n:-0}" -ne 32 ]; then
      echo "compose env preflight: PROBECTL_ENVELOPE_KEY must be base64 of exactly 32 bytes (openssl rand -base64 32), or empty to generate one on first boot" >&2; fail=1
    fi
  fi

  if grep -Eq '^[[:space:]]*PROBECTL_TLS_HOSTS=' "$file"; then
    v="$(env_value "$file" PROBECTL_TLS_HOSTS)"
    if [ -z "$v" ]; then
      echo "compose env preflight: PROBECTL_TLS_HOSTS is set but blank — the quickstart certificate would carry no hostnames" >&2; fail=1
    fi
  fi

  v="$(env_value "$file" PROBECTL_AUTH_MODE)"
  case "${v:-session}" in
    session)
      if [ -z "$(env_value "$file" PROBECTL_OIDC_ISSUER)" ]; then
        echo "compose env preflight: note — PROBECTL_AUTH_MODE=session with no PROBECTL_OIDC_ISSUER in .env; logins will fail closed unless an overlay (deploy/compose/dex-demo.yml) or the environment provides the OIDC values" >&2
      fi
      ;;
    dev) ;;
    *) echo "compose env preflight: PROBECTL_AUTH_MODE must be session or dev" >&2; fail=1 ;;
  esac

  v="$(env_value "$file" PROBECTL_LICENSE_PATH)"
  if [ -n "$v" ] && [ ! -r "$v" ]; then
    echo "compose env preflight: PROBECTL_LICENSE_PATH=$v is not a readable file (the offline-signed license from your vendor; docs/editions.md)" >&2; fail=1
  fi

  v="$(env_value "$file" PROBECTL_TLS_DIR)"
  if [ -n "$v" ]; then
    if [ ! -d "$v" ] || [ ! -s "$v/tls.crt" ] || [ ! -s "$v/tls.key" ]; then
      echo "compose env preflight: PROBECTL_TLS_DIR=$v must be a directory containing tls.crt and tls.key (and the issuing chain as ca.crt)" >&2; fail=1
    fi
  fi

  # DPR-010: the optional control.env beside .env is loaded by the control
  # service; every assignment there must be a PROBECTL_* key so a stray
  # POSTGRES_* or shell line cannot leak into the control plane environment.
  local ctl="$(dirname "$file")/control.env" line
  if [ -f "$ctl" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      line="$(trim "${line%%#*}")"
      [ -n "$line" ] || continue
      case "$line" in
        PROBECTL_[A-Z0-9_]*=*) ;;
        *) echo "compose env preflight: control.env may only contain PROBECTL_* assignments; found: ${line%%=*}" >&2; fail=1 ;;
      esac
    done <"$ctl"
  fi

  if [ "$fail" -ne 0 ]; then
    return 2
  fi
  echo "compose env preflight: OK ($file)"
}

selftest() {
  local tmp good
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  good="$tmp/good.env"
  cat >"$good" <<GOOD
POSTGRES_PASSWORD=selftest-not-a-secret
PROBECTL_ENVELOPE_KEY=
PROBECTL_SESSION_HMAC_KEY=0123456701234567012345670123456701234567012345670123456701234567
PROBECTL_TLS_HOSTS=localhost,127.0.0.1
PROBECTL_AUTH_MODE=session
PROBECTL_OIDC_ISSUER=https://idp.example.com
GOOD
  PROBECTL_COMPOSE_ENV_FILE="$good" bash "$0" >/dev/null || { echo "selftest: a valid .env must pass" >&2; exit 1; }

  expect_fail() { # expect_fail <label> <sed-expression>
    local label="$1" expr="$2"
    local f="$tmp/$label.env"
    sed "$expr" "$good" >"$f"
    if PROBECTL_COMPOSE_ENV_FILE="$f" bash "$0" >/dev/null 2>&1; then
      echo "selftest: planted failure '$label' was NOT caught" >&2; exit 1
    fi
  }
  expect_fail base64-password 's|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=abc/def+ghi=|'
  expect_fail at-in-password 's|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=p@ss|'
  expect_fail empty-password 's|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=|'
  expect_fail short-hmac 's|^PROBECTL_SESSION_HMAC_KEY=.*|PROBECTL_SESSION_HMAC_KEY=0123abcd|'
  expect_fail non-hex-hmac 's|^PROBECTL_SESSION_HMAC_KEY=.*|PROBECTL_SESSION_HMAC_KEY=zz23456701234567012345670123456701234567012345670123456701234567|'
  expect_fail short-envelope 's|^PROBECTL_ENVELOPE_KEY=.*|PROBECTL_ENVELOPE_KEY=c2hvcnQ=|'
  expect_fail blank-tls-hosts 's|^PROBECTL_TLS_HOSTS=.*|PROBECTL_TLS_HOSTS=|'
  expect_fail bad-auth-mode 's|^PROBECTL_AUTH_MODE=.*|PROBECTL_AUTH_MODE=none|'
  expect_fail missing-license 's|^PROBECTL_AUTH_MODE=.*|PROBECTL_LICENSE_PATH=/nonexistent/license.json|'
  expect_fail missing-tls-dir 's|^PROBECTL_AUTH_MODE=.*|PROBECTL_TLS_DIR=/nonexistent/certs|'
  # a quoted URL-safe password and a valid 32-byte envelope key pass
  sed -e 's|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD="quoted-Safe_value.ok~"|' -e 's|^PROBECTL_ENVELOPE_KEY=.*|PROBECTL_ENVELOPE_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|' "$good" >"$tmp/quoted.env"
  PROBECTL_COMPOSE_ENV_FILE="$tmp/quoted.env" bash "$0" >/dev/null || { echo "selftest: quoted URL-safe password + 32-byte envelope key must pass" >&2; exit 1; }
  if PROBECTL_COMPOSE_ENV_FILE="$tmp/does-not-exist.env" bash "$0" >/dev/null 2>&1; then
    echo "selftest: a missing .env must fail" >&2; exit 1
  fi
  # DPR-010: control.env beside .env may only carry PROBECTL_* keys
  printf 'PROBECTL_LOG_LEVEL=debug\n# comment\n\n' >"$tmp/control.env"
  PROBECTL_COMPOSE_ENV_FILE="$good" bash "$0" >/dev/null || { echo "selftest: a PROBECTL_*-only control.env must pass" >&2; exit 1; }
  printf 'PROBECTL_LOG_LEVEL=debug\nPOSTGRES_PASSWORD=leak\n' >"$tmp/control.env"
  if PROBECTL_COMPOSE_ENV_FILE="$good" bash "$0" >/dev/null 2>&1; then
    echo "selftest: a non-PROBECTL key in control.env must be rejected" >&2; exit 1
  fi
  rm -f "$tmp/control.env"
  echo "compose env preflight selftest: OK"
}

case "${1:-}" in
  SELFTEST) selftest ;;
  *) check_env "$ENV_FILE" ;;
esac
