#!/usr/bin/env bash
# verify-all (Sprint 25): the single executed-verification umbrella closing
# the diligence "STATIC-ONLY" methodology caveat. Runs build + vet/lint +
# race-detector tests + the repo guards + vulnerability/supply scans + the
# eBPF object compile, tee-ing EVERY output into receipts/ so diligence gets
# executed receipts, not static claims. Each step is BLOCKING (pipefail);
# a missing required tool FAILS the run — silently skipping a verification
# would recreate the exact gap this closes.
#
# Load + attach of the compiled BPF objects needs a kernel and runs in the
# ebpf-kernel-matrix CI job (QEMU, real LTS kernels) — the CI verify-all
# umbrella REQUIRES that job; locally this script proves the compile half
# when clang+bpftool are present.
set -euo pipefail
cd "$(dirname "$0")/.."

RECEIPTS="${RECEIPTS_DIR:-receipts}"
mkdir -p "$RECEIPTS"
note() { printf '\n==> %s\n' "$*"; }

run_step() { # run_step <receipt-name> <cmd...>
  local name="$1"; shift
  note "$name: $*"
  ( set -o pipefail; "$@" 2>&1 | tee "$RECEIPTS/$name.txt" )
}

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "verify-all: required tool '$1' not found — $2" >&2
    exit 1
  }
}

run_step build        make build
run_step lint         make lint
# test-race runs `go test -race -count=1 ./...` in EVERY module dir
# (GO_MODULE_DIRS = . test), i.e. the full package tree — no package is
# hand-listed or excluded, so a green here means every package compiled+ran
# (the flow/outage suites included). A "verify-all green" claim is only valid
# if this step actually passed across ./... — don't infer green from a subset.
run_step test-race    make test
run_step test-python  make test-python
run_step supply-pins  ./scripts/check_supply_pins.sh
run_step editions     make editions-gate
run_step openapi      make openapi-gate

note "govulncheck (BLOCKING)"
( set -o pipefail; go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./... 2>&1 | tee "$RECEIPTS/govulncheck.txt" )

require trivy "install from https://aquasecurity.github.io/trivy (CI uses trivy-action v0.36.0 with the same flags)"
run_step trivy-fs trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 .

require clang "the eBPF object compile needs clang+llvm (apt install clang llvm bpftool)"
require bpftool "needed to generate vmlinux.h from the build host's BTF"
run_step ebpf-compile make ebpf-agent

note "verify-all: ALL GREEN — receipts under $RECEIPTS/"
ls -l "$RECEIPTS"
