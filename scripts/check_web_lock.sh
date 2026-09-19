#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# check_web_lock.sh (DPR-236) — web/package-lock.json must install with `npm ci`
# under the npm that CI and deploy/docker/Dockerfile actually use.
#
# Why this exists rather than a static lint: lock↔package.json consistency is
# npm's own tree resolution, and it is not derivable from the lock file alone. An
# earlier attempt to approximate it PASSED the exact lock that broke CI, which is
# worse than no check. `npm ci --dry-run` is the real answer and costs 3 seconds.
#
# What it catches, both observed for real:
#   EUSAGE        a node the tree needs is absent — `npm audit fix
#                 --package-lock-only` deleted vitest's nested esbuild without
#                 re-resolving the vite that wanted it (ac90177).
#   EBADPLATFORM  platform binaries recorded non-optional, so npm tries to install
#                 @esbuild/netbsd-arm64 on linux/x64 (an npm 11-written lock).
#
# Neither is visible locally from an already-populated node_modules: `npm audit`,
# the policy gate and the whole test suite pass while `npm ci` cannot install at
# all. Eleven of fourteen failing CI jobs came from one of these.
#
#   scripts/check_web_lock.sh            # check the committed lock
#   SELFTEST=1 scripts/check_web_lock.sh # prove the check catches both shapes
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# The same digest-pinned image as deploy/docker/Dockerfile's web stage, on the
# amd64 platform the images are built for.
# The digest is a LITERAL here, not a variable: SUPPLY-002 requires every docker
# image operand to be statically a digest, and a variable defeats that check.
# internal/cipolicy TestWebNodeImageMatchesTheDockerfile keeps it equal to
# deploy/docker/Dockerfile's web stage.
PLATFORM="${PROBECTL_WEB_NODE_PLATFORM:-linux/amd64}"

if ! command -v docker >/dev/null 2>&1; then
  echo "check_web_lock: docker is required to run the pinned npm — refusing to report a clean lock it never installed" >&2
  exit 127
fi

# dry_run <package.json> <package-lock.json> -> prints npm's error code, exits non-zero on failure.
#
# The mount arguments are built BEFORE the docker line: the workflow-image policy
# (SUPPLY-002) parses docker commands statically to prove the image operand is a
# digest, and a command substitution inside -v defeats that parse.
dry_run() {
  local pj="$1" lock="$2" out pj_mount lock_mount
  pj_mount="$(cd "$(dirname "$pj")" && pwd)/$(basename "$pj"):/s/package.json:ro"
  lock_mount="$(cd "$(dirname "$lock")" && pwd)/$(basename "$lock"):/s/package-lock.json:ro"
  out="$(mktemp)"
  if docker run --rm --platform "$PLATFORM" -v "$pj_mount" -v "$lock_mount" \
      -e npm_config_update_notifier=false -e HOME=/tmp \
      node:22-bookworm-slim@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752 \
      bash -c 'mkdir -p /b && cp /s/package*.json /b/ && cd /b && npm ci --dry-run --no-audit --no-fund' \
      > "$out" 2>&1; then
    rm -f "$out"
    return 0
  fi
  grep -m1 -oE 'npm error code [A-Z]+' "$out" | awk '{print $NF}' || echo UNKNOWN
  rm -f "$out"
  return 1
}

if [ "${SELFTEST:-0}" = "1" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cp web/package.json "$tmp/package.json"

  # (a) a node the tree needs, deleted — the ac90177 shape.
  python3 - "$tmp/missing-lock.json" <<'PY'
import json, sys
lock = json.load(open('web/package-lock.json'))
pk = lock['packages']
victim = next((k for k in pk if k.endswith('node_modules/vitest/node_modules/esbuild')), None)
if victim is None:
    victim = next(k for k in pk if k.endswith('node_modules/esbuild'))
del pk[victim]
json.dump(lock, open(sys.argv[1], 'w'), indent=2)
print(f"planted: removed {victim}", file=sys.stderr)
PY
  if code="$(dry_run "$tmp/package.json" "$tmp/missing-lock.json")"; then
    echo "check_web_lock SELFTEST FAILED: a lock with a deleted node was accepted" >&2
    exit 1
  fi
  echo "check_web_lock SELFTEST: deleted node rejected (${code})"

  # (b) platform binaries marked required — the npm 11 shape.
  python3 - "$tmp/nonopt-lock.json" <<'PY'
import json, sys
lock = json.load(open('web/package-lock.json'))
n = 0
for name, p in lock['packages'].items():
    if (p.get('os') or p.get('cpu')) and p.get('optional'):
        p.pop('optional'); n += 1
json.dump(lock, open(sys.argv[1], 'w'), indent=2)
print(f"planted: made {n} platform binaries required", file=sys.stderr)
PY
  if code="$(dry_run "$tmp/package.json" "$tmp/nonopt-lock.json")"; then
    echo "check_web_lock SELFTEST FAILED: a lock with required platform binaries was accepted" >&2
    exit 1
  fi
  echo "check_web_lock SELFTEST: required platform binaries rejected (${code})"

  # (c) the real lock must pass, or the selftest proves nothing.
  if ! dry_run web/package.json web/package-lock.json >/dev/null; then
    echo "check_web_lock SELFTEST FAILED: the committed lock does not install" >&2
    exit 1
  fi
  echo "check_web_lock SELFTEST: OK (both planted shapes rejected, the real lock installs)"
  exit 0
fi

if code="$(dry_run web/package.json web/package-lock.json)"; then
  echo "check_web_lock: OK (web/package-lock.json installs with the pinned npm on ${PLATFORM})"
  exit 0
fi
echo "::error::check_web_lock: web/package-lock.json does NOT install (npm error ${code}). Regenerate it with the pinned npm: scripts/web_npm.sh install --package-lock-only" >&2
exit 1
