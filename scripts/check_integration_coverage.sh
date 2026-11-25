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
# CI instruments these packages across the full integration run. Tests often
# exercise storage and transport through control-plane entry points in another
# package. Keep the floors for the exact packages in this table.
#
#   check_integration_coverage.sh            measure each package locally
#   check_integration_coverage.sh PACKAGES   emit the CI -coverpkg list
#   check_integration_coverage.sh PROFILE FILE
#                                            enforce floors on the full suite
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

module_path() {
  awk '$1 == "module" { print $2; exit }' "$repo_root/go.mod"
}

package_list() {
  local module
  module="$(module_path)"
  [ -n "$module" ] || return 1
  awk -F '\t' -v module="$module" 'NF { printf "%s%s/%s", first ? "," : "", module, $1; first=1 } END { print "" }' <<<"$FLOORS"
}

package_profile() { # package_profile <combined profile> <exact import path>
  awk -v prefix="$2/" '
    NR == 1 {
      if ($0 !~ /^mode: (set|count|atomic)$/) exit 1
      print
      next
    }
    index($1, prefix) == 1 && index(substr($1, length(prefix) + 1), "/") == 0 {
      print
      records++
    }
    END { if (!records) exit 1 }
  ' "$1"
}

selftest() {
  # A value under the floor must be flagged; a value at or above must not. This
  # is the planted-defect check: it proves a real coverage drop would fail the
  # gate even when the stack is not available to run the suites.
  below_floor 44.9 45 || { echo "selftest: 44.9 < 45 must be below floor" >&2; exit 1; }
  if below_floor 45.0 45; then echo "selftest: 45.0 is not below the 45 floor" >&2; exit 1; fi
  if below_floor 80.1 80; then echo "selftest: 80.1 is not below the 80 floor" >&2; exit 1; fi
  below_floor 0 45 || { echo "selftest: 0 < 45 must be below floor" >&2; exit 1; }
  local fixture picked
  fixture="$(cat <<'PROFILE'
mode: set
example.test/control/rollout.go:1.1,1.9 1 0
example.test/control/rollout.go:1.1,1.9 1 1
example.test/control/sibling/item.go:1.1,1.9 1 1
example.test/controller/item.go:1.1,1.9 1 1
PROFILE
)"
  picked="$(package_profile /dev/stdin example.test/control <<<"$fixture")"
  if [ "$picked" != "$(printf '%s\n' "$fixture" | head -3)" ]; then
    echo "selftest: profile extraction must retain every sample for the exact package" >&2
    exit 1
  fi
  if package_profile /dev/stdin example.test/missing <<<"$fixture" >/dev/null; then
    echo "selftest: a missing package must fail" >&2
    exit 1
  fi
  echo "integration-coverage gate self-test OK"
}

run_gate() {
  local tmp; tmp="$(mktemp -d)"; trap "rm -rf '$tmp'" RETURN
  local combined="${1:-}" module
  module="$(module_path)"
  [ -n "$module" ] || return 1
  local fails=0
  printf '%-28s %8s %7s   %s\n' "PACKAGE" "COVER" "FLOOR" "STATUS"
  printf -- '----------------------------------------------------------\n'
  while IFS=$'\t' read -r pkg floor; do
    [ -n "$pkg" ] || continue
    local prof="$tmp/${pkg//\//_}.out" pct
    if [ -n "$combined" ]; then
      if ! package_profile "$combined" "$module/$pkg" >"$prof"; then
        printf '%-28s %8s %7s   %s\n' "$pkg" "?" "$floor" "NO-PROFILE"
        fails=$((fails + 1))
        continue
      fi
    elif ! ( cd "$repo_root" && "$go_cmd" test -tags integration -count=1 -timeout=60m \
            -coverprofile="$prof" "./$pkg/" ) >"$tmp/log" 2>&1; then
      printf '%-28s %8s %7s   %s\n' "$pkg" "-" "$floor" "TEST-FAIL"
      # Test failures can end with a large rendered DOM or locator dump. The
      # final five lines hide the failing test and assertion; retain the actual
      # captured failure before the temporary directory is removed.
      cat "$tmp/log" >&2
      fails=$((fails + 1))
      continue
    fi
    if ! pct="$(cd "$repo_root" && "$go_cmd" tool cover -func="$prof" | awk '/^total:/ {gsub(/%/,"",$3); print $3}')" || [ -z "$pct" ]; then
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
  PACKAGES) package_list ;;
  PROFILE)
    if [ "$#" -ne 2 ] || [ ! -s "$2" ]; then
      echo "coverage: a nonempty integration profile is required" >&2
      exit 1
    fi
    run_gate "$2"
    ;;
  "") run_gate ;;
  *) echo "usage: $0 [SELFTEST | PACKAGES | PROFILE FILE]" >&2; exit 2 ;;
esac
