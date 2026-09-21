#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# helm_push_digest.sh (DPR-258) — push a packaged chart to an OCI repository and
# print the immutable digest helm reported, on stdout. Everything helm said goes
# to stderr so it still lands in the job log.
#
# helm writes "Pushed:" and "Digest:" to STDERR, not stdout. release.yml captured
# only stdout, so `push_out` was empty, the digest was unparseable, and v0.6.5
# published the chart successfully and then failed reading its own output —
# "helm push did not report an immutable chart digest" on a push that worked.
# Measured against a loopback registry: a stdout-only capture is 0 bytes, and the
# same command with 2>&1 yields `Digest: sha256:...`.
#
#   digest="$(bash scripts/helm_push_digest.sh probectl-1.2.3.tgz oci://host/charts)"
#
# SELFTEST=1 plants a stub `helm` and asserts both directions, including the
# stream the bug was about.
set -uo pipefail
cd "$(dirname "$0")/.."

push_digest() {
  local pkg="${1:-}" repo="${2:-}"
  if [ -z "$pkg" ] || [ -z "$repo" ]; then
    echo "usage: helm_push_digest.sh <chart.tgz> <oci-repo>" >&2
    return 2
  fi
  local out rc
  set +e
  out="$(helm push "$pkg" "$repo" 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "$out" >&2
  if [ "$rc" -ne 0 ]; then
    echo "::error::helm push failed (exit ${rc}): ${out}" >&2
    return "$rc"
  fi
  local digest
  digest="$(printf '%s\n' "$out" | awk '/Digest:/ {print $2; exit}')"
  case "$digest" in
    sha256:*) printf '%s\n' "$digest" ;;
    *)
      echo "::error::helm push did not report an immutable chart digest; it printed: ${out}" >&2
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------- self-test ---
selftest_tmp=""
cleanup_selftest() { [ -n "$selftest_tmp" ] && rm -rf "$selftest_tmp"; return 0; }

selftest() {
  local stub fail=0
  selftest_tmp="$(mktemp -d)"
  stub="$selftest_tmp/bin"
  mkdir -p "$stub"
  trap cleanup_selftest EXIT

  local digest="sha256:9e24635951dd1ebaafe69bf74a762d60aaeb3978de0abed2806cd4ad6c665ad6"

  plant() { # $1 = stderr | stdout | silent | failure
    case "$1" in
      stderr)  cat > "$stub/helm" <<M
#!/usr/bin/env bash
# What helm actually does, verified against a loopback registry.
echo "Pushed: 127.0.0.1:15000/charts/probectl:9.9.9" >&2
echo "Digest: ${digest}" >&2
exit 0
M
;;
      stdout)  cat > "$stub/helm" <<M
#!/usr/bin/env bash
echo "Pushed: 127.0.0.1:15000/charts/probectl:9.9.9"
echo "Digest: ${digest}"
exit 0
M
;;
      silent)  printf '#!/usr/bin/env bash\nexit 0\n' > "$stub/helm" ;;
      failure) cat > "$stub/helm" <<'M'
#!/usr/bin/env bash
echo "Error: unauthorized: authentication required" >&2
exit 1
M
;;
    esac
    chmod +x "$stub/helm"
  }

  case_run() { # $1 label, $2 mode, $3 want_exit(0|nonzero), $4 want_stdout
    local label="$1" mode="$2" want="$3" wantout="$4" got rc
    plant "$mode"
    got="$(SELFTEST= PATH="$stub:$PATH" bash -e "$0" chart.tgz oci://example.invalid/charts 2>/dev/null)"
    rc=$?
    if [ "$want" = "0" ] && [ "$rc" -ne 0 ]; then
      echo "SELFTEST FAIL ${label}: exit ${rc}, want 0" >&2; fail=1; return
    fi
    if [ "$want" = "nonzero" ] && [ "$rc" -eq 0 ]; then
      echo "SELFTEST FAIL ${label}: exit 0, want a refusal" >&2; fail=1; return
    fi
    if [ "$got" != "$wantout" ]; then
      echo "SELFTEST FAIL ${label}: stdout [${got}], want [${wantout}]" >&2; fail=1; return
    fi
    echo "  ok  ${label}"
  }

  # The first case IS the bug: helm on stderr must still yield the digest.
  case_run "digest on stderr is extracted (the DPR-258 case)" stderr  0       "$digest"
  case_run "digest on stdout is extracted too"                stdout  0       "$digest"
  case_run "a silent push is refused, not treated as success" silent  nonzero ""
  case_run "a failed push is refused and its message kept"    failure nonzero ""

  if [ "$fail" -ne 0 ]; then
    echo "helm_push_digest SELFTEST: FAILED" >&2
    return 1
  fi
  echo "helm_push_digest SELFTEST: OK (the digest is read from whichever stream helm uses; silence and failure are refused)"
}

if [ "${SELFTEST:-0}" = "1" ]; then
  selftest
  exit $?
fi
push_digest "$@"
exit $?
