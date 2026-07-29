#!/usr/bin/env bash
#
# enrollment-scoping gate (TENANT-009/TENANT-e48658fb):
# agent_enroll_tokens / agent_identities fail closed when the tenant GUC is
# absent. Consume is the sole bare-pool authentication path and may call only
# its exact-hash SECURITY DEFINER function. Deployment-wide token cancellation
# and deny-list reads enter tenancy.InProvider and call provider-only functions.
# Every known-tenant table operation remains under tenancy.InTenant.
#
# It scans internal/store/enrollment.go: any e.pool/a.pool query whose SQL names
# agent_enroll_tokens or agent_identities outside Consume fails the build.
set -euo pipefail
cd "$(dirname "$0")/.."

FILE="internal/store/enrollment.go"
fail=0

# Lines doing a bare-pool DB call (pool.Query/QueryRow/Exec) — these must only
# appear only inside Consume. We implement that with awk tracking the enclosing
# function; Revoke and ListRevoked now enter the provider role instead.
offenders="$(awk '
  /^func / {
    fn=$0
    inpre = (fn ~ /func \(e EnrollTokens\) Consume/)
  }
  /(e\.pool|a\.pool)\.(Query|QueryRow|Exec)\(/ {
    if (!inpre) printf("%d: %s\n", NR, $0)
  }
' "$FILE" || true)"

if [ -n "${offenders}" ]; then
  echo "BARE-POOL enrollment query outside exact-hash Consume (TENANT-009 — route known-tenant ops through InTenant and global maintenance through InProvider):" >&2
  echo "${offenders}" >&2
  fail=1
fi

for required in \
  'FROM pretenant_consume_agent_enroll_token' \
  'tenancy.InProvider(ctx, e.pool' \
  'provider_revoke_agent_enroll_token' \
  'tenancy.InProvider(ctx, a.pool' \
  'provider_list_revoked_agent_identities'
do
  if ! grep -Fq "${required}" "${FILE}"; then
    echo "missing strict enrollment boundary wiring: ${required}" >&2
    fail=1
  fi
done

# self-test: a planted bare-pool call in a non-pre-tenant func must be caught.
if [ "${SELFTEST:-0}" = "1" ]; then
  probe="$(printf 'func (a AgentIdentities) Leak(ctx context.Context) {\n a.pool.Query(ctx, "SELECT * FROM agent_identities")\n}\n')"
  caught="$(printf '%s\n' "$probe" | awk '
    /^func / { inpre = ($0 ~ /func \(e EnrollTokens\) Consume/) }
    /(e\.pool|a\.pool)\.(Query|QueryRow|Exec)\(/ { if (!inpre) print }
  ')"
  [ -n "$caught" ] || { echo "SELFTEST FAILED: enrollment-scoping gate missed a planted bare-pool leak" >&2; exit 1; }
fi

[ "${fail}" -eq 0 ] || exit 1
echo "enrollment-scoping gate: OK (strict RLS; exact-hash Consume; provider-only global maintenance)"
