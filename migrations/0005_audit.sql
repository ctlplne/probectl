-- 0005_audit.sql
-- Audit foundation (F23-foundation): immutable, tamper-evident, hash-chained
-- logs. Two SEPARATE streams (CLAUDE.md §7 guardrail 7):
--   * audit_events          — tenant-scoped (RLS), one hash chain per tenant
--   * provider_audit_events — the provider-plane / break-glass stream (global)
-- Each row's `hash` chains over the previous row's hash, so any tampering breaks
-- the chain. Hashing is performed in Go via internal/crypto (the FIPS-swappable
-- abstraction), never in SQL.

CREATE TABLE IF NOT EXISTS audit_events (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    seq        bigint NOT NULL,                 -- per-tenant monotonic position
    actor      text NOT NULL,
    action     text NOT NULL,
    target     text NOT NULL DEFAULT '',
    data       jsonb NOT NULL DEFAULT '{}',
    prev_hash  text NOT NULL,
    hash       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, seq)
);
CREATE INDEX IF NOT EXISTS audit_events_tenant_seq_idx ON audit_events (tenant_id, seq);

CREATE TABLE IF NOT EXISTS provider_audit_events (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seq        bigint NOT NULL UNIQUE,          -- global monotonic position
    actor      text NOT NULL,                   -- provider operator / system
    action     text NOT NULL,
    target     text NOT NULL DEFAULT '',
    data       jsonb NOT NULL DEFAULT '{}',
    prev_hash  text NOT NULL,
    hash       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- audit_events is tenant-scoped AND append-only for the application role: a
-- SELECT policy and an INSERT policy exist, but deliberately NO UPDATE/DELETE
-- policy, so RLS denies mutation of recorded events.
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_select ON audit_events;
CREATE POLICY audit_select ON audit_events FOR SELECT
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS audit_insert ON audit_events;
CREATE POLICY audit_insert ON audit_events FOR INSERT
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
