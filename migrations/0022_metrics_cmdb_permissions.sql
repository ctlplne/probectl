-- 0022_metrics_cmdb_permissions.sql — S40 (F30): metrics remote-write + CMDB
-- read permissions.
--
-- metrics.read (the Grafana datasource / federation read side) already exists
-- (migration 0015, shared with the AI query layer). This migration adds the
-- remote-write ingest permission and the CMDB lookup permission. Idempotent +
-- expand-only (CLAUDE.md §6); the tenant boundary is enforced before RBAC.

INSERT INTO permissions (key, description) VALUES
    ('metrics.write', 'Ingest metrics via the Prometheus remote-write receiver'),
    ('cmdb.read',     'Look up and correlate CMDB configuration items')
ON CONFLICT (key) DO NOTHING;

-- metrics.write is a write capability: admin + editor only.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'metrics.write'
    FROM roles r
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug IN ('admin', 'editor')
ON CONFLICT (role_id, permission_key) DO NOTHING;

-- cmdb.read is a read capability: all seeded roles.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'cmdb.read'
    FROM roles r
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug IN ('admin', 'editor', 'viewer')
ON CONFLICT (role_id, permission_key) DO NOTHING;
