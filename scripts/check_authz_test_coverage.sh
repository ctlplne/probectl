#!/usr/bin/env bash
# check_authz_test_coverage.sh — per-route authorization denial coverage
# (Foundation-Loop S-e0e73b57).
#
# The shared dev test principal holds every permission, which made
# requirePermission a pass-through for the handler suites: ~40 suites nominally
# traversed it and only a handful ever observed a refusal — the lane that
# produced nine authorization-bypass findings was the lane the tests exercised
# least.
#
# The coverage is DERIVED from the route table rather than hand-written per
# file: for every route in apiRoutes(), the harness issues the request with
# that route's own permission withheld and requires a refusal. A new route is
# covered the moment it is registered, because the coverage IS the table.
# Routes that declare no permission, or that hide behind an unmounted
# capability, are classified in the test with a written reason and a pointer to
# where their denial IS proven; a stale classification fails.
#
# SELFTEST proves the harness can observe a refusal at all — a fully-privileged
# principal must NOT be refused and a withheld permission MUST be — so the
# coverage test cannot pass vacuously.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "SELFTEST" ]; then
  go test ./internal/control -run 'TestRouteDenialCoverageCanFail' -count=1
  exit $?
fi

go test ./internal/control -run 'TestEveryRouteRefusesAnUnderPrivilegedPrincipal|TestRouteDenialCoverageCanFail' -count=1
