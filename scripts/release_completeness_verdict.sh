#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#
# release_completeness_verdict.sh (decision D-15, 2026-09-20) — run the strict
# capability-ledger gate, print the whole verdict, and decide what a release is
# allowed to do with it:
#
#   ledger complete        -> full release   exit 0, prerelease=false
#   gaps on a 0.x tag      -> PRE-RELEASE    exit 0, prerelease=true
#   gaps on any other tag  -> refused        exit = the gate's own status
#   any other gate failure -> refused always exit = the gate's own status
#
# The oracle is untouched. This runs `make completeness-release-gate`, the same
# command with the same verdict, prints every blocking row it named (DPR-251),
# and never reinterprets a failure it cannot attribute to declared gaps. 0.x is
# the only version range where a declared gap does not block, which is the
# distinction docs/quality/completeness.md already draws by reserving the strict
# form for a FINAL release. A 0.x release that carries gaps says so on its own
# GitHub release page: `gaps` and `prerelease` are consumed by the binaries job.
#
# Env: GITHUB_REF_NAME (required, the tag) · GITHUB_OUTPUT (optional)
#      SELFTEST=1 plants every case and asserts both directions.
set -uo pipefail
cd "$(dirname "$0")/.."

emit() { # name=value -> the step's outputs, when running under Actions
  if [ -n "${GITHUB_OUTPUT:-}" ]; then printf '%s\n' "$1" >> "$GITHUB_OUTPUT"; fi
}

verdict() {
  local tag="${GITHUB_REF_NAME:-}"
  if [ -z "$tag" ]; then
    echo "release_completeness_verdict: GITHUB_REF_NAME is unset; refusing to guess the release tag" >&2
    return 2
  fi

  # errexit is off for exactly this command: the runner's default shell is
  # `bash -e`, and the gate is EXPECTED to exit non-zero here. Without this the
  # step would die before the verdict could be read.
  local out rc
  set +e
  out="$(make completeness-release-gate 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "$out"

  local gaps=0
  if [ "$rc" -ne 0 ]; then
    gaps="$(printf '%s\n' "$out" |
      sed -n 's/.*incomplete (\([0-9]\{1,\}\) acknowledged gap.*/\1/p' | head -1)"
    # A non-zero exit with no parsable count is a DIFFERENT failure — an invalid
    # registry, a broken toolchain — and must never be read as "some gaps, carry
    # on". No outputs are written, so nothing downstream can consume a verdict
    # this script did not reach.
    if [ -z "$gaps" ]; then
      echo "::error::the completeness gate failed for a reason other than acknowledged gaps; refusing the release" >&2
      return "$rc"
    fi
  fi

  emit "gaps=${gaps}"
  if [ "$gaps" -gt 0 ]; then emit "prerelease=true"; else emit "prerelease=false"; fi

  if [ "$rc" -eq 0 ]; then
    echo "capability ledger is 100% complete; ${tag} publishes a full release"
    return 0
  fi
  case "$tag" in
    v0 | v0.*)
      echo "::warning::${tag} publishes as a PRE-RELEASE: the capability ledger records ${gaps} acknowledged gap(s) (decision D-15). Every blocking row is listed above."
      return 0
      ;;
    *)
      echo "::error::${tag} is not a 0.x tag, so the capability ledger must be 100% complete before it publishes; ${gaps} acknowledged gap(s) remain." >&2
      return "$rc"
      ;;
  esac
}

# ---------------------------------------------------------------- self-test ---
# Plants a stub `make` so every branch is exercised without a 30s ledger render,
# and asserts the refusal direction as hard as the permissive one: the whole
# point of D-15 is that 0.x is the ONLY range a declared gap does not block.
# The scratch dir is a global because the EXIT trap outlives selftest's locals,
# and under `set -u` a trap referencing a dead local kills the script AFTER it
# has already reported OK.
selftest_tmp=""
cleanup_selftest() { [ -n "$selftest_tmp" ] && rm -rf "$selftest_tmp"; return 0; }

selftest() {
  local stub fail=0
  selftest_tmp="$(mktemp -d)"
  stub="$selftest_tmp/bin"
  mkdir -p "$stub"
  trap cleanup_selftest EXIT

  plant() { # $1 = gaps|clean|broken
    case "$1" in
      gaps)
        cat > "$stub/make" <<'M'
#!/usr/bin/env bash
echo "completeness-gate: incomplete (60 acknowledged gap(s); 650/710 spine cells covered)" >&2
echo "  - F1.real_stack_proof [agent/security] Canary agent: PLANTED-ROW-DETAIL" >&2
echo "blocking cells by dimension: ui=2 real_stack_proof=58" >&2
exit 1
M
        ;;
      clean)
        cat > "$stub/make" <<'M'
#!/usr/bin/env bash
echo "completeness-gate: OK (71 capabilities, 710/710 spine cells covered; 0 acknowledged gap(s))"
exit 0
M
        ;;
      broken)
        cat > "$stub/make" <<'M'
#!/usr/bin/env bash
echo "completeness: 2 violation(s):" >&2
echo "  - F1.cli [missing-cell]: the registry itself is invalid" >&2
exit 2
M
        ;;
    esac
    chmod +x "$stub/make"
  }

  case_run() { # $1 label, $2 tag, $3 stub, $4 want_exit(0|nonzero), $5 want_outputs
    local label="$1" tag="$2" mode="$3" want="$4" wantout="$5" rc out got
    plant "$mode"
    local outfile="$selftest_tmp/out"
    : > "$outfile"
    # SELFTEST must be cleared for the child, or it re-enters this function
    # instead of running the verdict and the selftest recurses forever.
    out="$(SELFTEST= PATH="$stub:$PATH" GITHUB_REF_NAME="$tag" GITHUB_OUTPUT="$outfile" \
      bash -e "$0" 2>&1)"
    rc=$?
    got="$(tr '\n' ' ' < "$outfile" | sed 's/ *$//')"
    if [ "$want" = "0" ] && [ "$rc" -ne 0 ]; then
      echo "SELFTEST FAIL ${label}: exit ${rc}, want 0" >&2; echo "$out" >&2; fail=1; return
    fi
    if [ "$want" = "nonzero" ] && [ "$rc" -eq 0 ]; then
      echo "SELFTEST FAIL ${label}: exit 0, want a refusal" >&2; echo "$out" >&2; fail=1; return
    fi
    if [ "$got" != "$wantout" ]; then
      echo "SELFTEST FAIL ${label}: outputs [${got}], want [${wantout}]" >&2; fail=1; return
    fi
    # Whatever the verdict, the blocking rows must reach the log: the gate's
    # output IS the work list, and a decision that hides it is worse than none.
    if [ "$mode" = "gaps" ] && ! printf '%s' "$out" | grep -q PLANTED-ROW-DETAIL; then
      echo "SELFTEST FAIL ${label}: the blocking rows were not printed" >&2; fail=1; return
    fi
    echo "  ok  ${label}"
  }

  case_run "0.x tag + gaps publishes a pre-release"      v0.6.4 gaps   0       "gaps=60 prerelease=true"
  case_run "bare v0 tag + gaps publishes a pre-release"  v0     gaps   0       "gaps=60 prerelease=true"
  case_run "1.0.0 + gaps is refused"                     v1.0.0 gaps   nonzero "gaps=60 prerelease=true"
  case_run "2.3.1 + gaps is refused"                     v2.3.1 gaps   nonzero "gaps=60 prerelease=true"
  case_run "complete ledger is a full 0.x release"       v0.6.4 clean  0       "gaps=0 prerelease=false"
  case_run "complete ledger is a full 1.x release"       v1.0.0 clean  0       "gaps=0 prerelease=false"
  case_run "a non-gap gate failure refuses even on 0.x"  v0.6.4 broken nonzero ""
  case_run "a non-gap gate failure refuses on 1.x too"   v1.0.0 broken nonzero ""

  # An unset tag must not be guessed at.
  plant clean
  if SELFTEST= PATH="$stub:$PATH" GITHUB_REF_NAME= bash -e "$0" >/dev/null 2>&1; then
    echo "SELFTEST FAIL: an unset GITHUB_REF_NAME was accepted" >&2; fail=1
  else
    echo "  ok  an unset tag is refused rather than guessed"
  fi

  if [ "$fail" -ne 0 ]; then
    echo "release_completeness_verdict SELFTEST: FAILED" >&2
    return 1
  fi
  echo "release_completeness_verdict SELFTEST: OK (0.x gaps publish a pre-release; every other tag and every non-gap failure is refused)"
}

if [ "${SELFTEST:-0}" = "1" ]; then
  selftest
  exit $?
fi
verdict
exit $?
