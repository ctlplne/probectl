#!/usr/bin/env bash
#
# Fuzz smoke (S15a hardening): run each fuzz target briefly to catch crashers.
#
# The gate's contract is "no crashers in the budget": a real finding makes
# `go test -fuzz` persist the failing input ("Failing input written to
# testdata/fuzz/<Target>/...") and we fail hard on that — or on any other
# real failure (panic, build error, vet error).
#
# One narrowly tolerated wart: on loaded CI runners the Go fuzz coordinator can
# report a bare "context deadline exceeded" when -fuzztime expires while a
# worker is mid-execution. That is a wind-down scheduling artifact, NOT a
# finding — but only when the run made real progress (it logged executions).
# TEST-007: we no longer blanket-tolerate the deadline. We tolerate it ONLY if
# the run actually executed inputs (an "elapsed: …, execs: N" line with N>0);
# a deadline with ZERO executions is a hang signature and FAILS. The single
# authoritative crasher signal (a persisted failing input) always fails, and
# the gate is NOT retried (a retry could mask a low-probability nondeterministic
# finding — RED/anti-vacuous-green discipline).
set -uo pipefail

GO="${GO:-go}"
FUZZ_SMOKE_TIME="${FUZZ_SMOKE_TIME:-10s}"

run_fuzz() { # name fuzztime pkg
  local name="$1" t="$2" pkg="$3"
  echo ">> fuzz ${name} (${t}) ${pkg}"
  local out rc
  out="$("$GO" test -run='^$' -fuzz="^${name}$" -fuzztime="$t" "$pkg" 2>&1)"
  rc=$?
  echo "$out"
  if [ "$rc" -eq 0 ]; then
    return 0
  fi
  if echo "$out" | grep -q "Failing input written to"; then
    echo "fuzz-smoke: ${name}: CRASHER FOUND (failing input persisted under testdata/fuzz/) — investigate before merging" >&2
    return 1
  fi
  if echo "$out" | grep -q "context deadline exceeded"; then
    # TEST-007: tolerate the wind-down deadline ONLY if the run actually made
    # progress. Go fuzz logs "elapsed: Ns, execs: N (M/sec)"; a nonzero execs
    # total means real work happened and the deadline is a scheduling artifact.
    # Zero executions under a deadline is a hang signature — fail it.
    if echo "$out" | grep -Eq 'execs: [1-9][0-9]*'; then
      echo "fuzz-smoke: WARNING: ${name} hit the -fuzztime wind-down deadline after real execution and with no crasher; tolerated (Go fuzz coordinator quirk on loaded runners)" >&2
      return 0
    fi
    echo "fuzz-smoke: ${name}: context deadline with ZERO executions — hang signature, not a wind-down artifact" >&2
    return 1
  fi
  echo "fuzz-smoke: ${name}: failed (rc=${rc})" >&2
  return 1
}

# TEST-003: discover targets dynamically so a newly-added fuzz function cannot
# silently miss PR smoke coverage. This covers FuzzVerifyBatchTenant and every
# future internal/ fuzz target unless the discovery policy fails.
found=0
while IFS=$'\t' read -r pkg name; do
  found=1
  run_fuzz "$name" "$FUZZ_SMOKE_TIME" "$pkg" || exit 1
done < <("$(dirname "$0")/list_fuzz_targets.sh")

if [ "$found" -eq 0 ]; then
  echo "fuzz-smoke: no fuzz targets discovered" >&2
  exit 1
fi

echo "fuzz-smoke: all targets clean"
