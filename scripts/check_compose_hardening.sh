#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# SUP-12: the production-shaped Compose stack (deploy/compose/probectl.yml) must
# ship HARDENED and VERIFYING by default. This gate renders the resolved config
# and asserts, service by service:
#   * no-new-privileges on every service;
#   * read-only root FS + cap_drop:[ALL] on the distroless control-image
#     one-shots and the serving control plane (certgen, migrate, control);
#   * a memory + PID ceiling on the Postgres and pg-appuser containers (whose
#     upstream entrypoints need root, so they keep a writable FS);
#   * bounded json-file logging on the long-running services (postgres, control);
#   * sslmode=verify-full (CA + hostname) on every control->Postgres DSN and the
#     pg-appuser provisioning hop — not merely sslmode=require (encrypt-only).
#
# The third SUP-12 leg — refusing to mint a KEK beside the data unless an
# explicit eval ack is set — is enforced by scripts/compose_env_preflight.sh
# (run from `make compose-prod-preflight`/`make compose-image-gate`), with its
# own SELFTEST.
#
#   check_compose_hardening.sh            render + enforce (needs docker compose)
#   check_compose_hardening.sh SELFTEST   prove the judge catches each regression
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$repo_root/deploy/compose/probectl.yml}"

judge() { # judge <compose-config-json-file> -> 0 ok, 1 on any violation
  CONFIG_JSON="$1" python3 - <<'PY'
import json, os, sys

cfg = json.load(open(os.environ["CONFIG_JSON"]))
services = cfg.get("services", {})
problems = []

CONTROL_IMAGE = {"certgen", "migrate", "control"}   # distroless, immutable-FS
LONG_RUNNING = {"postgres", "control"}              # need bounded logs
DB_DSN_SERVICES = {"migrate", "control"}            # PROBECTL_DATABASE_URL

def secopt(svc):
    return svc.get("security_opt") or []

for name, svc in services.items():
    if not any("no-new-privileges" in str(o) and "true" in str(o) for o in secopt(svc)):
        problems.append(f"{name}: missing security_opt no-new-privileges:true")

for name in CONTROL_IMAGE:
    svc = services.get(name, {})
    if svc.get("read_only") is not True:
        problems.append(f"{name}: control-image service must set read_only:true")
    cap_drop = svc.get("cap_drop") or []
    if "ALL" not in cap_drop:
        problems.append(f"{name}: control-image service must cap_drop:[ALL]")

for name in ("postgres", "pg-appuser"):
    svc = services.get(name, {})
    # compose config renders mem_limit as mem_limit (bytes) and pids_limit as pids_limit
    if not svc.get("mem_limit"):
        problems.append(f"{name}: missing mem_limit")
    if svc.get("pids_limit") in (None, 0):
        problems.append(f"{name}: missing pids_limit")

for name in LONG_RUNNING:
    svc = services.get(name, {})
    log = svc.get("logging") or {}
    if log.get("driver") != "json-file" or not (log.get("options") or {}).get("max-size"):
        problems.append(f"{name}: long-running service must set bounded json-file logging")

def env_of(svc):
    e = svc.get("environment") or {}
    if isinstance(e, list):  # list form "K=V"
        out = {}
        for item in e:
            k, _, v = str(item).partition("=")
            out[k] = v
        return out
    return e

for name in DB_DSN_SERVICES:
    dsn = str(env_of(services.get(name, {})).get("PROBECTL_DATABASE_URL", ""))
    if "sslmode=verify-full" not in dsn:
        problems.append(f"{name}: PROBECTL_DATABASE_URL must use sslmode=verify-full (got: {dsn or 'unset'})")
    if "sslrootcert=" not in dsn:
        problems.append(f"{name}: PROBECTL_DATABASE_URL must pin sslrootcert for verify-full")

appcmd = " ".join(str(x) for x in (services.get("pg-appuser", {}).get("entrypoint")
                                    or services.get("pg-appuser", {}).get("command") or []))
if "sslmode=verify-full" not in appcmd:
    problems.append("pg-appuser: provisioning psql must use sslmode=verify-full")

if problems:
    print("::error::SUP-12: compose hardening/verify-full violations:", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    sys.exit(1)
print(f"SUP-12: compose stack hardened + verify-full across {len(services)} services")
PY
}

run_gate() {
  command -v docker >/dev/null || { echo "::error::SUP-12: docker not found" >&2; exit 1; }
  local tmp; tmp="$(mktemp)"; trap "rm -f '$tmp'" RETURN
  POSTGRES_PASSWORD=ci-validate-only \
  POSTGRES_APP_PASSWORD=ci-validate-only \
  PROBECTL_SESSION_HMAC_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  PROBECTL_IMAGE=ghcr.io/ctlplne/probectl-control:v0.4.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    docker compose -f "$COMPOSE_FILE" config --format json > "$tmp"
  judge "$tmp"
}

selftest() {
  local tmp; tmp="$(mktemp)"; trap "rm -f '$tmp'" RETURN
  # Compliant synthetic config must pass.
  cat > "$tmp" <<'JSON'
{"services":{
 "postgres":{"security_opt":["no-new-privileges:true"],"mem_limit":"1g","pids_limit":512,"logging":{"driver":"json-file","options":{"max-size":"10m"}}},
 "pg-appuser":{"security_opt":["no-new-privileges:true"],"mem_limit":"256m","pids_limit":128,"entrypoint":["bash","-c","psql host=postgres sslmode=verify-full sslrootcert=/certs/ca.crt"]},
 "certgen":{"security_opt":["no-new-privileges:true"],"read_only":true,"cap_drop":["ALL"]},
 "migrate":{"security_opt":["no-new-privileges:true"],"read_only":true,"cap_drop":["ALL"],"environment":{"PROBECTL_DATABASE_URL":"postgres://x@postgres/probectl?sslmode=verify-full&sslrootcert=/certs/ca.crt"}},
 "control":{"security_opt":["no-new-privileges:true"],"read_only":true,"cap_drop":["ALL"],"logging":{"driver":"json-file","options":{"max-size":"10m"}},"environment":{"PROBECTL_DATABASE_URL":"postgres://x@postgres/probectl?sslmode=verify-full&sslrootcert=/certs/ca.crt"}}
}}
JSON
  judge "$tmp" >/dev/null || { echo "selftest: a compliant config must pass" >&2; exit 1; }

  planted() { # planted <jq-ish python mutation> — expect judge to FAIL
    local label="$1" mutate="$2" f="$tmp.$1"
    CONFIG_IN="$tmp" MUT="$mutate" python3 - "$f" <<'PY'
import json, os, sys
c = json.load(open(os.environ["CONFIG_IN"]))
exec(os.environ["MUT"])
json.dump(c, open(sys.argv[1], "w"))
PY
    if judge "$tmp.$1" >/dev/null 2>&1; then
      echo "selftest: planted defect '$label' was NOT caught" >&2; exit 1
    fi
  }
  planted drop-nnp           'c["services"]["control"]["security_opt"]=[]'
  planted require-dsn        'c["services"]["control"]["environment"]["PROBECTL_DATABASE_URL"]="postgres://x@postgres/probectl?sslmode=require"'
  planted no-readonly        'c["services"]["migrate"]["read_only"]=False'
  planted no-caps            'c["services"]["certgen"]["cap_drop"]=[]'
  planted no-logcap          'c["services"]["postgres"]["logging"]={}'
  planted appuser-require    'c["services"]["pg-appuser"]["entrypoint"]=["bash","-c","psql host=postgres sslmode=require"]'
  echo "compose-hardening gate self-test OK"
}

case "${1:-}" in
  SELFTEST) selftest ;;
  *) run_gate ;;
esac
