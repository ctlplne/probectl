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

run_fuzz FuzzParseICMPv4       15s ./internal/path/ || exit 1
run_fuzz FuzzParseTimeExceeded 15s ./internal/path/ || exit 1
run_fuzz FuzzEmbeddedEcho      10s ./internal/path/ || exit 1
run_fuzz FuzzIngest            15s ./internal/bgp/  || exit 1
# U-082: every externally-fed parser carries a fuzz target.
run_fuzz FuzzDecode            15s ./internal/flow/      || exit 1
run_fuzz FuzzSNMPPoll          10s ./internal/device/    || exit 1
run_fuzz FuzzGNMINormalize     10s ./internal/device/    || exit 1
run_fuzz FuzzOTLPPayload       15s ./internal/otel/otlp/ || exit 1
run_fuzz FuzzParseBeacon       10s ./internal/rum/       || exit 1
# FUZZ-004: the backup container header/frame length math (restore path).
run_fuzz FuzzBackupOpen        10s ./internal/backup/    || exit 1
# FUZZ-002: the L7 application-protocol parsers — the rawest attacker-controlled
# content on a privileged host agent (HTTP/1, HTTP/2, gRPC, Kafka, DNS framing).
run_fuzz FuzzL7Manager         15s ./internal/ebpf/l7/   || exit 1
run_fuzz FuzzL7Detect          10s ./internal/ebpf/l7/   || exit 1
run_fuzz FuzzKafkaScan         10s ./internal/ebpf/l7/   || exit 1
run_fuzz FuzzHTTP1Scan         10s ./internal/ebpf/l7/   || exit 1
run_fuzz FuzzHTTP2Frame        10s ./internal/ebpf/l7/   || exit 1

echo "fuzz-smoke: all targets clean"
