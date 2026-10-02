-- 0114_siem_delivery_claim.sql — AUD-16: a short-lived per-tenant export claim
-- on the SIEM delivery cursor.
--
-- The audit poller now POSTs a batch of events to the SIEM with NO database
-- transaction open (so a slow/large tenant never pins a connection across the
-- network I/O), then advances the cursor in a short follow-up transaction. The
-- claim (owner + lease deadline) is what serializes delivery across overlapping
-- replicas during failover without holding a transaction across the POST: a
-- replica only forwards a page it holds the claim for, and the cursor advance is
-- a compare-and-set on last_seq. Both columns are nullable and have no default,
-- so this is an additive, instant, zero-downtime change (N-1 code ignores them).
-- RLS already confines every siem_delivery row to its tenant (migration 0019).

ALTER TABLE siem_delivery
    ADD COLUMN IF NOT EXISTS claim_owner text;
ALTER TABLE siem_delivery
    ADD COLUMN IF NOT EXISTS claim_until timestamptz;

COMMENT ON COLUMN siem_delivery.claim_owner IS
    'AUD-16: per-instance owner id holding the current export claim; NULL when unclaimed.';
COMMENT ON COLUMN siem_delivery.claim_until IS
    'AUD-16: lease deadline for claim_owner; a claim past this instant is stealable so a crashed poller cannot stall a tenant.';
