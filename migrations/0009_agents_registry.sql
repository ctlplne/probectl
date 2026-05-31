-- 0009_agents_registry.sql
-- Extend the agents placeholder (S2) into the agent registry (S4). An agent
-- belongs to exactly one tenant (F50); its id and tenant are derived from its
-- mTLS certificate's SPIFFE identity, so every result it later emits is
-- tenant-attributable at the source. tenant_id + RLS already exist from S2;
-- these columns are additive and idempotent.

ALTER TABLE agents ADD COLUMN IF NOT EXISTS hostname      text NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_version text NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS status        text NOT NULL DEFAULT 'registered'
    CHECK (status IN ('registered', 'online', 'offline'));
ALTER TABLE agents ADD COLUMN IF NOT EXISTS capabilities  jsonb NOT NULL DEFAULT '[]';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS spiffe_id     text NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS registered_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_seen_at  timestamptz;

CREATE INDEX IF NOT EXISTS agents_status_idx ON agents (tenant_id, status);
