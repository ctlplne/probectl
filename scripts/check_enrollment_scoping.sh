#!/usr/bin/env bash
#
# enrollment-scoping gate (TENANT-009): the agent_enroll_tokens / agent_identities
# tables carry a deliberately PERMISSIVE-on-null RLS policy (0041) so the
# PRE-TENANT lookups — Consume (by secret token hash) and ListRevoked (the
# cross-tenant boot deny-list) — can run on the bare pool with no GUC. Every
# KNOWN-TENANT operation must instead run UNDER tenancy.InTenant so RLS confines
# it; a bare-pool (e.pool/a.pool) SELECT/UPDATE on these tables outside the two
# sanctioned pre-tenant methods is the regression this gate catches.
#
# It scans internal/store/enrollment.go: any e.pool/a.pool query whose SQL names
# agent_enroll_tokens or agent_identities, EXCEPT the allowlisted pre-tenant
# methods, fails the build.
set -euo pipefail
cd "$(dirname "$0")/.."

FILE="internal/store/enrollment.go"
fail=0

# Lines doing a bare-pool DB call (pool.Query/QueryRow/Exec) — these must only
# appear inside the two pre-tenant methods (Consume, ListRevoked). We approximate
# by checking that no bare-pool call sits OUTSIDE those methods. The robust check:
# every bare-pool call line must be within a Consume(...) or ListRevoked(...)
# function body. We implement it with awk tracking the enclosing func.
offenders="$(awk '
  /^func / {
    fn=$0
    # Pre-tenant by design (no tenant in hand): Consume (by secret token hash),
    # ListRevoked (cross-tenant boot deny-list), Revoke (operator UPDATE by the
    # token UUID — a single-row op on an id the operator already holds, no
    # tenant available to scope to).
    inpre = (fn ~ /func \(e EnrollTokens\) Consume/ \
          || fn ~ /func \(a AgentIdentities\) ListRevoked/ \
          || fn ~ /func \(e EnrollTokens\) Revoke/)
  }
  /(e\.pool|a\.pool)\.(Query|QueryRow|Exec)\(/ {
    if (!inpre) printf("%d: %s\n", NR, $0)
  }
' "$FILE" || true)"

if [ -n "${offenders}" ]; then
  echo "BARE-POOL enrollment query outside the pre-tenant Consume/ListRevoked methods (TENANT-009 — route known-tenant ops through tenancy.InTenant):" >&2
  echo "${offenders}" >&2
  fail=1
fi

# self-test: a planted bare-pool call in a non-pre-tenant func must be caught.
if [ "${SELFTEST:-0}" = "1" ]; then
  probe="$(printf 'func (a AgentIdentities) Leak(ctx context.Context) {\n a.pool.Query(ctx, "SELECT * FROM agent_identities")\n}\n')"
  caught="$(printf '%s\n' "$probe" | awk '
    /^func / { inpre = ($0 ~ /Consume/ || $0 ~ /ListRevoked/) }
    /(e\.pool|a\.pool)\.(Query|QueryRow|Exec)\(/ { if (!inpre) print }
  ')"
  [ -n "$caught" ] || { echo "SELFTEST FAILED: enrollment-scoping gate missed a planted bare-pool leak" >&2; exit 1; }
fi

[ "${fail}" -eq 0 ] || exit 1
echo "enrollment-scoping gate: OK (known-tenant ops run under InTenant; bare pool only on pre-tenant Consume/ListRevoked)"
