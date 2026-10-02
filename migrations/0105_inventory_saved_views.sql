-- 0105_inventory_saved_views.sql
-- PLAT-06: durable, tenant-scoped storage for inventory saved views (operator
-- UI/config state: filter choices, not inventory rows). They were
-- process-memory only, lost on restart and not shared between replicas.
-- tenant_id + FORCE ROW LEVEL SECURITY from creation (guardrail 1).

CREATE TABLE IF NOT EXISTS inventory_saved_views (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_id   text        NOT NULL,
    surface    text        NOT NULL,
    name       text        NOT NULL,
    filters    jsonb       NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS inventory_saved_views_tenant_owner_idx
    ON inventory_saved_views (tenant_id, owner_id, surface, created_at DESC);

DO $$
BEGIN
    EXECUTE 'ALTER TABLE inventory_saved_views ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE inventory_saved_views FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON inventory_saved_views';
    EXECUTE $pol$
        CREATE POLICY tenant_isolation ON inventory_saved_views
          USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
          WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    $pol$;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON inventory_saved_views TO probectl_app;
