#!/usr/bin/env bash
# check_authz_chokepoint.sh — the authorization-chokepoint gate (Foundation-Loop
# S-6357f747). One evaluator (auth.Decide: tenant → RBAC → ABAC deny), reached
# through declared doors only:
#   - mux registrations in internal/control only inside (*Server).routes
#   - the evaluation primitives callable only from the declared chokepoint files
#   - every MCP tool declares a Permission
#   - every provider route wrapped, or listed in providerPublicAuthPatterns
#     with a reason (exact correspondence, both directions)
# SELFTEST drives planted violations of every shape through the SAME analysis
# functions the live checks use.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "SELFTEST" ]; then
  go test ./internal/cipolicy -run 'TestAuthzChokepointSelfTestCatchesPlantedViolations' -count=1
  exit $?
fi

go test ./internal/cipolicy -run 'TestAuthzChokepoint' -count=1
