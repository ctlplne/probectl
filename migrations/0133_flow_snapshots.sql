-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- Recomputable, creator-private result cache; private_header MUST NOT enter
-- ordinary or subject portability bundles. Original telemetry is exported.
CREATE TABLE IF NOT EXISTS flow_snapshot_epochs (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    generation bigint NOT NULL CHECK (generation >= 1),
    invalidating boolean NOT NULL,
    transition_token uuid,
    CHECK (invalidating = (transition_token IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS flow_snapshots (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    owner_id text NOT NULL CHECK (octet_length(owner_id) BETWEEN 1 AND 1024),
    generation bigint NOT NULL CHECK (generation >= 1),
    query_hash text NOT NULL CHECK (query_hash ~ '^[0-9a-f]{64}$'),
    object_lane text NOT NULL CHECK (object_lane IN ('pooled','silo')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    row_count integer NOT NULL CHECK (row_count BETWEEN 0 AND 50000),
    page_size integer NOT NULL CHECK (page_size BETWEEN 1 AND 5000),
    permissions text[] NOT NULL CHECK (cardinality(permissions) BETWEEN 1 AND 64),
    private_header text NOT NULL CHECK (octet_length(private_header) BETWEEN 1 AND 65536),
    charged_bytes bigint NOT NULL CHECK (charged_bytes > 0),
    state text NOT NULL CHECK (state IN ('pending','ready')),
    PRIMARY KEY (tenant_id,id)
);
CREATE INDEX IF NOT EXISTS flow_snapshots_tenant_expiry_idx ON flow_snapshots(tenant_id,expires_at,id);
ALTER TABLE flow_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE flow_snapshot_epochs ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_snapshot_epochs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON flow_snapshots;
CREATE POLICY tenant_isolation ON flow_snapshots
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_isolation ON flow_snapshot_epochs;
CREATE POLICY tenant_isolation ON flow_snapshot_epochs
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON flow_snapshots,flow_snapshot_epochs TO probectl_app;

-- New tenant-owned tables participate in the canonical offboarding fence
-- from their first creation, including table-owner and replication writes.
DROP TRIGGER IF EXISTS tenant_write_fence ON flow_snapshot_epochs;
CREATE TRIGGER tenant_write_fence
    BEFORE INSERT OR UPDATE ON flow_snapshot_epochs
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE flow_snapshot_epochs ENABLE ALWAYS TRIGGER tenant_write_fence;
DROP TRIGGER IF EXISTS tenant_write_fence ON flow_snapshots;
CREATE TRIGGER tenant_write_fence
    BEFORE INSERT OR UPDATE ON flow_snapshots
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE flow_snapshots ENABLE ALWAYS TRIGGER tenant_write_fence;
