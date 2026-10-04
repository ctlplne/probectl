-- 0119_usage_flush_batch_idempotency.sql — AUD-21: billing-critical losslessness.
--
-- usage_flush_batches is the metering recorder's idempotency ledger. Every
-- flush carries a stable batch id; ee/billing.PGStore.AddCounters claims that
-- id here IN THE SAME TRANSACTION as the counter upserts. A commit the recorder
-- only saw fail makes it retry the batch with the SAME id — the retry finds the
-- ledger row and applies nothing, so a counter is never doubled (docs/metering.md:
-- "never lost and never double-counted"). The ledger is pruned to a short window
-- (retries are in flight for seconds to minutes), so it stays small.
--
-- This is provider-plane data belonging to NO single tenant (a batch spans
-- tenants), owned and reached only by probectl_provider, never copied into a
-- tenant silo schema (billing stays pooled, like usage_records). It carries no
-- tenant_id column, so the boot isolation posture check does not — and should
-- not — require a tenant RLS policy on it; it still FORCEs RLS behind a
-- provider-only policy so probectl_app can never reach it.
--
-- Idempotent + expand-only (CLAUDE.md §6).

CREATE TABLE IF NOT EXISTS usage_flush_batches (
    batch_id   text        PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS usage_flush_batches_applied_idx ON usage_flush_batches (applied_at);

ALTER TABLE usage_flush_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_flush_batches FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS provider_metering ON usage_flush_batches;
CREATE POLICY provider_metering ON usage_flush_batches
    FOR ALL TO probectl_provider USING (true) WITH CHECK (true);

GRANT SELECT, INSERT, DELETE ON usage_flush_batches TO probectl_provider;
