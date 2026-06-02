-- 0015_ai_feedback.sql
-- AI assistant (S24, F13): answer-feedback capture (the answer-quality loop) plus
-- the RBAC permission keys the unified semantic query layer (S23) enforces per
-- domain, and the ai.query capability that gates the assistant surface. Tenant-
-- owned: tenant_id + Row-Level Security confine every row to its tenant (F50), so
-- feedback never crosses tenants. Idempotent + backward-compatible.

CREATE TABLE IF NOT EXISTS ai_feedback (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    answer_id   text        NOT NULL,
    question    text        NOT NULL DEFAULT '',
    rating      text        NOT NULL,
    comment     text        NOT NULL DEFAULT '',
    user_id     text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ai_feedback_tenant_idx ON ai_feedback (tenant_id, created_at DESC);

ALTER TABLE ai_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_feedback FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_feedback;
CREATE POLICY tenant_isolation ON ai_feedback
  USING (tenant_id = NULLIF(current_setting('netctl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('netctl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT ON ai_feedback TO netctl_app;

-- Permission keys: the per-domain read perms the S23 query layer enforces (the
-- two-level boundary checks the tenant first, then these), plus ai.query which
-- gates the assistant. Idempotent.
INSERT INTO permissions (key, description) VALUES
    ('ai.query',      'Use the AI assistant (RCA / natural-language query)'),
    ('metrics.read',  'Read metrics via the unified query layer'),
    ('events.read',   'Read events/flows via the unified query layer'),
    ('entities.read', 'Read entities (incidents/tests/agents) via the unified query layer'),
    ('topology.read', 'Read the topology graph via the unified query layer')
ON CONFLICT (key) DO NOTHING;

-- Grant the new keys to the seeded system roles of the default tenant. admin gets
-- all; viewer + editor get the read perms and ai.query (the assistant is a
-- read-only capability). Other tenants are seeded at provisioning (S-T1).
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, p.key
    FROM roles r CROSS JOIN permissions p
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug IN ('admin', 'editor', 'viewer')
      AND p.key IN ('ai.query', 'metrics.read', 'events.read', 'entities.read', 'topology.read')
ON CONFLICT (role_id, permission_key) DO NOTHING;
