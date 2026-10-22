#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# TEST-003: prove the fuzz gates are structurally honest. The PR smoke gate
# must discover every fuzz target, and the nightly workflow must either fit its
# whole fuzz budget inside the job timeout or shard targets with a matrix.
#
# S-7f81b4c2 adds ATTACK-SURFACE PARITY on top of that budget honesty: budget
# checks cannot see a parser with no target at all, so every parser of
# untrusted input must be bound in docs/fuzz/parser_register.json to a target
# that exists (or carry a written exemption). SELFTEST proves the parity rule
# can fail by planting an unregistered parser.
set -euo pipefail

if [ "${1:-}" = "SELFTEST" ]; then
  cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  go test ./internal/cipolicy -run 'TestFuzzParitySelfTestCatchesAnUnregisteredParser' -count=1
  exit $?
fi

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
  $'./internal/canary\tFuzzDNSDoHResponseSummary' \
  $'./internal/canary\tFuzzHTTPExpectAndDrain' \
  $'./internal/ebpf\tFuzzL4DecodeFlowSample'
do
  if ! "$LIST" | grep -q "$pair"; then
    echo "fuzz-policy: ${pair} is not discovered" >&2
    exit 1
  fi
done

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

for pair in \
  $'./internal/change\tFuzzChangeNormalize' \
  $'./internal/notify\tFuzzParseInbound'
do
  if ! "$LIST" | grep -q "$pair"; then
    echo "fuzz-policy: ${pair} is not discovered" >&2
    exit 1
  fi
done

if ! "$LIST" | grep -q $'./internal/ai/mcp\tFuzzMCPHandle'; then
  echo "fuzz-policy: FuzzMCPHandle is not discovered" >&2
  exit 1
fi

if ! "$LIST" | grep -q $'./ee/provider\tFuzzProviderDecode'; then
  echo "fuzz-policy: FuzzProviderDecode is not discovered" >&2
  exit 1
fi

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

# G6: count budgets. Each row's measurement is a 10-minute run, so a budget at
# or below its measurement fits a 10m-or-longer job timeout the same way the
# duration budget does. A row must name a discovered target (a stale row is a
# budget protecting nothing) and the workflow must actually run the count.
BUDGETS="$ROOT/docs/fuzz/nightly_budget.tsv"
budgeted=0
if [ -f "$BUDGETS" ]; then
  if [ "$timeout_seconds" -lt 600 ]; then
    echo "fuzz-policy: count budgets are calibrated on 10m runs but the job timeout is ${nightly_timeout_minutes}m" >&2
    exit 1
  fi
  if ! grep -q 'matrix.fuzztime' "$NIGHTLY"; then
    echo "fuzz-policy: ${BUDGETS#"$ROOT"/} exists but nightly.yml never runs matrix.fuzztime" >&2
    exit 1
  fi
  discovered="$("$LIST" | cut -f2)"
  while IFS=$'\t' read -r name measured budget extra; do
    case "$name" in ''|'#'*) continue ;; esac
    if [ -n "${extra:-}" ] || ! [[ "$measured" =~ ^[0-9]+$ && "$budget" =~ ^[0-9]+$ ]] || [ "$budget" -le 0 ]; then
      echo "fuzz-policy: malformed budget row for ${name} (want name<TAB>measured_execs_10m<TAB>budget_execs)" >&2
      exit 1
    fi
    if ! printf '%s\n' "$discovered" | grep -qx "$name"; then
      echo "fuzz-policy: budget row ${name} names no discovered fuzz target" >&2
      exit 1
    fi
    if [ "$budget" -gt "$measured" ]; then
      echo "fuzz-policy: ${name} budget ${budget}x exceeds its 10m measurement ${measured}" >&2
      exit 1
    fi
    budgeted=$((budgeted + 1))
  done < "$BUDGETS"
fi

( cd "$ROOT" && go test ./internal/cipolicy -run 'TestFuzzParity' -count=1 ) || {
  echo "fuzz-policy: attack-surface parity failed (see docs/fuzz/parser_register.json)" >&2
  exit 1
}

echo "fuzz-policy: OK (${target_count} targets discovered; nightly is matrix-sharded; ${budgeted} on count budgets within their 10m measurement, the rest ${nightly_fuzztime} <= ${nightly_timeout_minutes}m)"
