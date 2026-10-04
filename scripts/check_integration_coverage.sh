#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# TQ-09: integration-coverage floors for the security-critical, stateful
# packages. The service-free unit gate (scripts/check_coverage.sh) deliberately
# exempts these — their meaningful coverage needs a real Postgres (RLS), the
# event store and the bus — so without this gate a regression that guts, say,
# the tenancy or audit paths would sail through at 3-27% unit coverage. This
# gate measures each package's statement coverage WITH its integration tests
# (the stack the `integration` CI job already brings up) and fails if any drops
# below its floor. It supersedes the single inline internal/store floor (U-057).
#
# Floors sit a few points below the coverage measured in CI (some tests need
# Kafka/ClickHouse that a Postgres-only run skips, so the real number is >=
# these); raise them as coverage grows, never lower one to make a regression
# pass.
#
#   check_integration_coverage.sh            measure + enforce (needs the stack)
#   check_integration_coverage.sh SELFTEST   prove the floor comparison is honest
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_cmd="${GO:-go}"

# pkg<TAB>floor. Keep import paths relative to the main module root.
FLOORS=$(cat <<'TABLE'
internal/store	60
internal/tenancy	40
internal/audit	65
internal/enroll	60
internal/agenttransport	70
internal/control	70
ee/silo	80
internal/tenantlife	72
TABLE
)

below_floor() { # below_floor <measured> <floor> -> 0 (true) if measured < floor
  awk -v p="$1" -v f="$2" 'BEGIN { exit !(p + 0 < f + 0) }'
}

selftest() {
  # A value under the floor must be flagged; a value at or above must not. This
  # is the planted-defect check: it proves a real coverage drop would fail the
  # gate even when the stack is not available to run the suites.
  below_floor 44.9 45 || { echo "selftest: 44.9 < 45 must be below floor" >&2; exit 1; }
  if below_floor 45.0 45; then echo "selftest: 45.0 is not below the 45 floor" >&2; exit 1; fi
  if below_floor 80.1 80; then echo "selftest: 80.1 is not below the 80 floor" >&2; exit 1; fi
  below_floor 0 45 || { echo "selftest: 0 < 45 must be below floor" >&2; exit 1; }
  echo "integration-coverage gate self-test OK"
}

run_gate() {
  local tmp; tmp="$(mktemp -d)"; trap "rm -rf '$tmp'" RETURN
  local fails=0
  printf '%-28s %8s %7s   %s\n' "PACKAGE" "COVER" "FLOOR" "STATUS"
  printf -- '----------------------------------------------------------\n'
  while IFS=$'\t' read -r pkg floor; do
    [ -n "$pkg" ] || continue
    local prof="$tmp/${pkg//\//_}.out" pct
    if ! ( cd "$repo_root" && "$go_cmd" test -tags integration -count=1 \
            -coverprofile="$prof" "./$pkg/" ) >"$tmp/log" 2>&1; then
      printf '%-28s %8s %7s   %s\n' "$pkg" "-" "$floor" "TEST-FAIL"
      tail -5 "$tmp/log" >&2
      fails=$((fails + 1))
      continue
    fi
    pct="$("$go_cmd" tool cover -func="$prof" 2>/dev/null | awk '/^total:/ {gsub(/%/,"",$3); print $3}')"
    if [ -z "$pct" ]; then
      printf '%-28s %8s %7s   %s\n' "$pkg" "?" "$floor" "NO-PROFILE"
      fails=$((fails + 1))
      continue
    fi
    if below_floor "$pct" "$floor"; then
      printf '%-28s %7s%% %7s   %s\n' "$pkg" "$pct" "$floor" "LOW"
      fails=$((fails + 1))
    else
      printf '%-28s %7s%% %7s   %s\n' "$pkg" "$pct" "$floor" "ok"
    fi
  done <<<"$FLOORS"
  printf -- '----------------------------------------------------------\n'
  if [ "$fails" -ne 0 ]; then
    echo "::error::TQ-09: ${fails} package(s) below their integration-coverage floor (or failed to measure)" >&2
    exit 1
  fi
  echo "integration-coverage gate: OK"
}

case "${1:-}" in
  SELFTEST) selftest ;;
  *) run_gate ;;
esac
