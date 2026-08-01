-- 0087: at most ONE consented, unrevoked, undenied break-glass grant per
-- (operator, tenant) at a time (Foundation-Loop S-ae06d833).
--
-- Consent/deny/revoke now take the row lock and re-state their preconditions as
-- UPDATE predicates, so a lost race fails closed in the transaction. This index
-- is the second half of that guarantee: it makes two simultaneously-decided
-- ACTIVE grants for the same operator+tenant unrepresentable in storage, so the
-- invariant no longer depends on any code path remembering to check. Expiry is
-- deliberately NOT in the predicate — a partial index cannot reference now(),
-- and an expired grant is inert to UseGrant regardless.
--
-- Expand-only and idempotent: adding a constraint, never dropping or rewriting.
-- A pre-existing duplicate (none is expected: the decision paths always
-- required consent to be a single transition) would surface here as a failed
-- migration rather than silently persisting; that is the intended fail-closed
-- behavior on the most-audited surface in the product.
-- lock-ok: break_glass_grants holds one row per human-initiated break-glass
-- REQUEST (an operator asking a tenant admin for time-bounded access). It is
-- orders of magnitude smaller than any telemetry table and takes no ingestion
-- traffic, so the brief ACCESS EXCLUSIVE lock cannot stall a data path.
CREATE UNIQUE INDEX IF NOT EXISTS break_glass_one_active_per_operator_tenant
    ON break_glass_grants (operator_id, tenant_id)
    WHERE consented_at IS NOT NULL
      AND denied_at IS NULL
      AND revoked_at IS NULL;
