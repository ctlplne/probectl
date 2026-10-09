-- 0123: an expired break-glass grant no longer blocks the next one (F51).
--
-- 0087 made at most one consented, undenied, unrevoked grant per
-- (operator, tenant) unrepresentable in storage. A partial index cannot
-- reference now(), so an EXPIRED grant still matched it: once an operator's
-- grant for a tenant simply ran out, every later consent for that operator and
-- tenant hit the index (409), and the expired grant could not be revoked to
-- clear it either (revoke refuses an expired grant). The operator was locked
-- out of break-glass for that tenant for good.
--
-- superseded_at marks an expired grant as no longer holding the slot. The
-- consent transaction stamps it on the expired grant it replaces, and the
-- index below ignores superseded rows. Only an expired grant is ever
-- superseded, so two simultaneously usable grants for one operator and tenant
-- stay unrepresentable. Grant state is still derived from the decision columns
-- and expires_at (an expired grant still reads "expired"); superseded_at only
-- releases the slot.
--
-- Expand-only and idempotent: a nullable column, the replacement index, then
-- dropping the index it replaces.
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS superseded_at timestamptz;

-- lock-ok: break_glass_grants holds one row per human-initiated break-glass
-- REQUEST (an operator asking a tenant admin for time-bounded access). It is
-- orders of magnitude smaller than any telemetry table and takes no ingestion
-- traffic, so the brief ACCESS EXCLUSIVE lock cannot stall a data path.
CREATE UNIQUE INDEX IF NOT EXISTS break_glass_one_live_per_operator_tenant
    ON break_glass_grants (operator_id, tenant_id)
    WHERE consented_at IS NOT NULL
      AND denied_at IS NULL
      AND revoked_at IS NULL
      AND superseded_at IS NULL;

DROP INDEX IF EXISTS break_glass_one_active_per_operator_tenant;
