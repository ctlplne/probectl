-- 0056_incident_share_artifacts.sql
-- X6: stable, redacted incident-room evidence snapshots. These are NOT public
-- bearer links: every read is authenticated and tenant-scoped. The artifact ID
-- is random and tenant_id remains the outermost storage boundary. Expiry is
-- mandatory and capped by the tenant's object-retention policy at creation.

CREATE TABLE IF NOT EXISTS incident_share_artifacts (
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id          text        NOT NULL,
    incident_id uuid        NOT NULL,
    payload     jsonb       NOT NULL,
    created_by  text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    PRIMARY KEY (tenant_id, id),
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS incident_share_artifacts_tenant_expiry_idx
    ON incident_share_artifacts (tenant_id, expires_at);

ALTER TABLE incident_share_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_share_artifacts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON incident_share_artifacts;
CREATE POLICY tenant_isolation ON incident_share_artifacts
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON incident_share_artifacts TO probectl_app;
