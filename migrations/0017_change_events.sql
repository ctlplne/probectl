-- 0017_change_events.sql
-- Change-intelligence events (S29, F39): normalized config/route/deploy/IaC/commit
-- changes ingested from per-provider signed webhooks. Tenant-owned: tenant_id +
-- Row-Level Security confine every row to its tenant (F50), so the change timeline
-- and change<->incident correlation never cross tenants. The tenant_id is stamped
-- from the VERIFIED webhook credential at the edge, NEVER from the (untrusted)
-- payload. `kind` is free-form and `attributes` is jsonb, so heterogeneous sources
-- attach detail without schema churn. Idempotent + backward-compatible.

CREATE TABLE IF NOT EXISTS change_events (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source      text        NOT NULL DEFAULT '',
    kind        text        NOT NULL DEFAULT 'other',
    title       text        NOT NULL DEFAULT '',
    summary     text        NOT NULL DEFAULT '',
    target      text        NOT NULL DEFAULT '',
    prefix      text        NOT NULL DEFAULT '',
    actor       text        NOT NULL DEFAULT '',
    ref         text        NOT NULL DEFAULT '',
    url         text        NOT NULL DEFAULT '',
    attributes  jsonb       NOT NULL DEFAULT '{}',
    occurred_at timestamptz NOT NULL DEFAULT now(),
    received_at timestamptz NOT NULL DEFAULT now(),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS change_events_tenant_idx ON change_events (tenant_id);
-- The timeline + correlation read recent changes for a tenant (optionally a target).
CREATE INDEX IF NOT EXISTS change_events_tenant_occurred_idx ON change_events (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS change_events_tenant_target_idx ON change_events (tenant_id, target);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['change_events']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format($pol$
            CREATE POLICY tenant_isolation ON %I
              USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
              WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
        $pol$, t);
    END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON change_events TO probectl_app;

-- Permission key gating the change timeline / correlation reads (the tenant
-- boundary is enforced first, then this). Idempotent.
INSERT INTO permissions (key, description) VALUES
    ('change.read', 'Read change events + change-to-incident correlation')
ON CONFLICT (key) DO NOTHING;

-- Grant change.read to the default tenant's seeded read roles (admin/editor/viewer);
-- other tenants are seeded at provisioning.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'change.read'
    FROM roles r
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug IN ('admin', 'editor', 'viewer')
ON CONFLICT (role_id, permission_key) DO NOTHING;
