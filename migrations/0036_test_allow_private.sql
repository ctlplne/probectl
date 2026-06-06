-- 0036: SSRF-guard override permission (U-002, C1).
--
-- Probe/canary targets are denied private/link-local/metadata destinations by
-- default (internal/canary SSRF guard). Setting allow_private_targets=true on
-- a test is the audited, tenant-scoped override — gated on this permission,
-- seeded to the system ADMIN role only (editor keeps test.write but cannot
-- lift the guard).
--
-- Idempotent + expand-only (CLAUDE.md §6).

INSERT INTO permissions (key, description) VALUES
    ('test.allow_private', 'Allow a test to target private/internal addresses (SSRF-guard override; audited)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'test.allow_private'
    FROM roles r
    WHERE r.slug = 'admin' AND r.is_system
ON CONFLICT (role_id, permission_key) DO NOTHING;
