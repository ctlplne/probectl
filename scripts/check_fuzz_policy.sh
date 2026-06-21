#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-probectl-TBD
#
# TEST-003: prove the fuzz gates are structurally honest. The PR smoke gate
# must discover every fuzz target, and the nightly workflow must either fit its
# whole fuzz budget inside the job timeout or shard targets with a matrix.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NIGHTLY="$ROOT/.github/workflows/nightly.yml"
SMOKE="$ROOT/scripts/fuzz_smoke.sh"
LIST="$ROOT/scripts/list_fuzz_targets.sh"

parse_duration_seconds() {
  local value="$1"
  case "$value" in
    *s) echo "${value%s}" ;;
    *m) echo "$(( ${value%m} * 60 ))" ;;
    *h) echo "$(( ${value%h} * 3600 ))" ;;
    *)
      echo "unsupported fuzz duration: $value" >&2
      return 1
      ;;
  esac
}

target_count="$("$LIST" --count)"
if [ "$target_count" -le 0 ]; then
  echo "fuzz-policy: no fuzz targets discovered" >&2
  exit 1
fi

if ! "$LIST" | grep -q $'./internal/pipeline\tFuzzVerifyBatchTenant'; then
  echo "fuzz-policy: FuzzVerifyBatchTenant is not discovered" >&2
  exit 1
fi

for target in FuzzOTLPTracePayload FuzzOTLPLogPayload; do
  if ! "$LIST" | grep -q $'./internal/otel/otlp\t'"$target"; then
    echo "fuzz-policy: ${target} is not discovered" >&2
    exit 1
  fi
done

if ! "$LIST" | grep -q $'./internal/promapi\tFuzzDecodeRemoteWrite'; then
  echo "fuzz-policy: FuzzDecodeRemoteWrite is not discovered" >&2
  exit 1
fi

for pair in \
  $'./internal/control\tFuzzDecodeSCIM' \
  $'./internal/scim\tFuzzApplyUserPatch' \
  $'./internal/scim\tFuzzParseGroupPatch'
do
  if ! "$LIST" | grep -q "$pair"; then
    echo "fuzz-policy: ${pair} is not discovered" >&2
    exit 1
  fi
done

if ! grep -q 'list_fuzz_targets.sh' "$SMOKE"; then
  echo "fuzz-policy: fuzz_smoke.sh must consume scripts/list_fuzz_targets.sh" >&2
  exit 1
fi

if ! grep -q 'fromJSON(needs.discover-fuzz-targets.outputs.matrix)' "$NIGHTLY"; then
  echo "fuzz-policy: nightly fuzz must be matrix-sharded from discovered targets" >&2
  exit 1
fi

nightly_timeout_minutes="$(awk '
  /^  fuzz:/ { in_fuzz=1; next }
  in_fuzz && /^  [A-Za-z0-9_-]+:/ { exit }
  in_fuzz && /timeout-minutes:/ { print $2; exit }
' "$NIGHTLY")"
if ! [[ "$nightly_timeout_minutes" =~ ^[0-9]+$ ]]; then
  echo "fuzz-policy: could not parse nightly fuzz timeout" >&2
  exit 1
fi

nightly_fuzztime="$(awk '
  /FUZZ_NIGHTLY_FUZZTIME:/ {
    gsub(/"/, "", $2)
    print $2
    exit
  }
' "$NIGHTLY")"
if [ -z "$nightly_fuzztime" ]; then
  echo "fuzz-policy: could not parse FUZZ_NIGHTLY_FUZZTIME" >&2
  exit 1
fi

budget_seconds="$(parse_duration_seconds "$nightly_fuzztime")"
timeout_seconds="$(( nightly_timeout_minutes * 60 ))"
if [ "$budget_seconds" -gt "$timeout_seconds" ]; then
  echo "fuzz-policy: per-target fuzztime ${nightly_fuzztime} exceeds job timeout ${nightly_timeout_minutes}m" >&2
  exit 1
fi

echo "fuzz-policy: OK (${target_count} targets discovered; nightly is matrix-sharded; ${nightly_fuzztime} <= ${nightly_timeout_minutes}m)"
