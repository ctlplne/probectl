#!/usr/bin/env bash
#
# agent_overhead.sh [output-file] — the reproducible agent-overhead run
# (U-051). Runs the userspace-pipeline benchmarks + the overhead report
# under identical settings everywhere (CI smoke, dev laptops, REFERENCE
# HOSTS for the whitepaper numbers, U-034) and records host context next
# to the numbers so a result is interpretable later.
set -euo pipefail
cd "$(dirname "$0")/../.."

OUT="${1:-}"
run() {
  echo "## host"
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -sr)  arch=$(uname -m)"
  grep -m1 'model name' /proc/cpuinfo 2>/dev/null || sysctl -n machdep.cpu.brand_string 2>/dev/null || true
  echo "cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?')"
  echo
  echo "## microbenchmarks (per event / per payload)"
  go test -bench . -benchtime 200000x -count 3 -run '^$' ./internal/ebpf/
  echo
  echo "## pipeline overhead report (throughput, CPU/event, RSS)"
  go test -count=1 -run '^TestAgentOverheadReport$' -v ./internal/ebpf/ | grep -E "AGENT OVERHEAD|core|PASS|FAIL"
}

if [ -n "${OUT}" ]; then
  run | tee "${OUT}"
  echo "wrote ${OUT} — paste the numbers into docs/agent-overhead.md"
else
  run
fi
