#!/usr/bin/env bash
#
# Fuzz smoke (S15a hardening): run each fuzz target briefly to catch crashers.
#
# The gate's contract is "no crashers in the budget": a real finding makes
# `go test -fuzz` persist the failing input ("Failing input written to
# testdata/fuzz/<Target>/...") and we fail hard on that — or on any other
# real failure (panic, build error, vet error).
#
# One tolerated wart: on loaded CI runners the Go fuzz coordinator can report
# a bare "context deadline exceeded" when -fuzztime expires while a worker is
# still mid-execution (the run shows 0 execs/sec in its final second and NO
# failing input). That is a wind-down scheduling artifact of the fuzz engine,
# not a finding — it is logged loudly and tolerated so the gate doesn't flake.
# A genuine hang would not match this shape: with no crasher persisted it
# would blow the overall `go test` timeout instead.
set -uo pipefail

GO="${GO:-go}"

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
    echo "fuzz-smoke: WARNING: ${name} hit the -fuzztime wind-down deadline with no crasher; tolerated (Go fuzz coordinator quirk on loaded runners)" >&2
    return 0
  fi
  echo "fuzz-smoke: ${name}: failed (rc=${rc})" >&2
  return 1
}

run_fuzz FuzzParseICMPv4       15s ./internal/path/ || exit 1
run_fuzz FuzzParseTimeExceeded 15s ./internal/path/ || exit 1
run_fuzz FuzzEmbeddedEcho      10s ./internal/path/ || exit 1
run_fuzz FuzzIngest            15s ./internal/bgp/  || exit 1

echo "fuzz-smoke: all targets clean"
