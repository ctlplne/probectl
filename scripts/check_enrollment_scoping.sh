#!/usr/bin/env bash
#
# enrollment-scoping gate (TENANT-009/TENANT-e48658fb):
# agent_enroll_tokens / agent_identities fail closed when the tenant GUC is
# absent. Since 62477bc the sole bare-pool authentication path is the shared
# credential-locator layer: pretenant_resolve_credential /
# pretenant_resolve_credential_id are exact-hash SECURITY DEFINER resolvers,
# and every enrollment mutation (consume, revoke) then runs under
# tenancy.InTenant RLS. Deployment-wide deny-list reads enter
# tenancy.InProvider and call the provider-only function.
#
# Two scans:
#   1. internal/store/enrollment.go must contain NO bare-pool DB call at all —
#      resolution goes through the credential locators, everything else through
#      InTenant/InProvider.
#   2. internal/store/credentiallocators.go may make bare-pool calls ONLY
#      inside resolveCredential / resolveCredentialID (the SECURITY DEFINER
#      resolvers); any other function doing a bare-pool call fails the build.
set -euo pipefail
cd "$(dirname "$0")/.."

ENROLL="internal/store/enrollment.go"
LOCATORS="internal/store/credentiallocators.go"
fail=0

bare_pool_census() { # bare_pool_census <file-or-dash-for-stdin> <allowed-func-regex>
  awk -v allowed="$2" '
    /^func / { fn=$0; inallowed = (fn ~ allowed) }
    /([a-z]\.pool|pool)\.(Query|QueryRow|Exec)\(/ {
      if (!inallowed) printf("%d: %s\n", NR, $0)
    }
  ' "$1"
}

# AgentCA rows (migration 0041) are the deployment's CA hierarchy — keyed by
# kind, no tenant_id column — so its repository is the one legitimately
# deployment-scoped bare-pool user in this file.
offenders="$(bare_pool_census "$ENROLL" '^func \\(c AgentCA\\)' || true)"
if [ -n "${offenders}" ]; then
  echo "BARE-POOL enrollment query (TENANT-009 — resolve via the credential locators, mutate under InTenant, deny-list reads under InProvider):" >&2
  echo "${offenders}" >&2
  fail=1
fi

offenders="$(bare_pool_census "$LOCATORS" '^func (resolveCredential|resolveCredentialID)\\(' || true)"
if [ -n "${offenders}" ]; then
  echo "BARE-POOL credential query outside the exact-hash SECURITY DEFINER resolvers:" >&2
  echo "${offenders}" >&2
  fail=1
fi

require_in() { # require_in <file> <fixed-string>
  if ! grep -Fq "$2" "$1"; then
    echo "missing strict enrollment boundary wiring in $1: $2" >&2
    fail=1
  fi
}

# The load-bearing wiring of the current architecture. If one of these moves,
# re-verify the fail-closed property end to end before renaming it here.
require_in "$LOCATORS" 'FROM pretenant_resolve_credential('
require_in "$LOCATORS" 'FROM pretenant_resolve_credential_id('
require_in "$ENROLL" 'tenancy.InProvider(ctx, a.pool'
require_in "$ENROLL" 'provider_list_revoked_agent_identities'

# self-test: both planted violation shapes must be caught BY THE SAME census
# function the live scans use — a copy of the logic would rot independently.
if [ "${SELFTEST:-0}" = "1" ]; then
  probe="$(printf 'func (a AgentIdentities) Leak(ctx context.Context) {\n a.pool.Query(ctx, "SELECT * FROM agent_identities")\n}\n')"
  caught="$(printf '%s\n' "$probe" | bare_pool_census - '^func \\(c AgentCA\\)' || true)"
  [ -n "$caught" ] || { echo "SELFTEST FAILED: enrollment-scoping gate missed a planted bare-pool leak" >&2; exit 1; }

  probe="$(printf 'func stealCredential(ctx context.Context, pool *pgxpool.Pool) {\n pool.QueryRow(ctx, "SELECT tenant_id FROM credential_locators")\n}\nfunc resolveCredential(\n ctx context.Context,\n) {\n pool.QueryRow(ctx, "SELECT 1")\n}\n')"
  caught="$(printf '%s\n' "$probe" | bare_pool_census - '^func (resolveCredential|resolveCredentialID)\\(' || true)"
  printf '%s\n' "$caught" | grep -Fq 'credential_locators' ||
    { echo "SELFTEST FAILED: locator gate missed a planted bare-pool call outside the resolvers" >&2; exit 1; }
  printf '%s\n' "$caught" | grep -Fq 'SELECT 1' &&
    { echo "SELFTEST FAILED: locator gate flagged the allowed resolver body" >&2; exit 1; }
  echo "enrollment-scoping self-test: OK (both planted violation shapes detected; resolver body allowed)"
fi

[ "${fail}" -eq 0 ] || exit 1
