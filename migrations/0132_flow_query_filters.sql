-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX1: reusable structured filters; no telemetry table or tenant selector is
-- accepted in the expression. Storage scope is mandatory from table creation.
CREATE TABLE IF NOT EXISTS flow_query_filters (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 256),
    description text NOT NULL DEFAULT '' CHECK (octet_length(description) <= 4096),
    expression jsonb NOT NULL CHECK (jsonb_typeof(expression) = 'object'
                                     AND octet_length(expression::text) <= 4194304),
    version bigint NOT NULL CHECK (version >= 1),
    updated_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS flow_query_filters_tenant_name_idx
    ON flow_query_filters (tenant_id, name, id);
ALTER TABLE flow_query_filters ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_query_filters FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON flow_query_filters;
CREATE POLICY tenant_isolation ON flow_query_filters
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON flow_query_filters TO probectl_app;

-- A new configuration capability does not grant writes to telemetry readers.
INSERT INTO permissions (key, description) VALUES
    ('flow.filters.write', 'Create, modify and delete tenant-shared flow query filters')
ON CONFLICT (key) DO NOTHING;
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'flow.filters.write' FROM roles r
    JOIN public.tenants t ON t.id = r.tenant_id
    WHERE r.slug = 'admin' AND r.is_system
      AND t.status IN ('active', 'suspended')
      AND t.audit_write_fenced_at IS NULL
ON CONFLICT (role_id, permission_key) DO NOTHING;

-- New tenant-owned tables participate in the canonical offboarding fence
-- from their first creation, including table-owner and replication writes.
DROP TRIGGER IF EXISTS tenant_write_fence ON flow_query_filters;
CREATE TRIGGER tenant_write_fence
    BEFORE INSERT OR UPDATE ON flow_query_filters
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE flow_query_filters ENABLE ALWAYS TRIGGER tenant_write_fence;
