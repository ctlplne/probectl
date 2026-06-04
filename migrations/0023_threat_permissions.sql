-- 0023_threat_permissions.sql — S-FE2 (M-FE): the security-plane read permission.
--
-- threat.read gates the TLS/cert posture inventory (/v1/tls/*, S-FE2) and the
-- coming threat/IOC triage surface (S-FE3). The inventory itself is in-memory
-- (rebuilt from the result stream) — this migration only seeds RBAC. The
-- tenant boundary is enforced before this check. Idempotent + expand-only
-- (CLAUDE.md §6).

INSERT INTO permissions (key, description) VALUES
    ('threat.read', 'Read security-plane surfaces: TLS/cert posture, threat detections')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'threat.read'
    FROM roles r
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug IN ('admin', 'editor', 'viewer')
ON CONFLICT (role_id, permission_key) DO NOTHING;
