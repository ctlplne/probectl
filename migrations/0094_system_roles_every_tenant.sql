-- SPDX-License-Identifier: BUSL-1.1
--
-- DPR-035: every tenant carries the three system roles. Migration 0013 seeded
-- admin/editor/viewer for the default tenant only and promised that other
-- tenants would be seeded at provisioning; provisioning never did, so a tenant
-- created through the provider plane had no role to bind and could not be
-- administered at all. Backfill every existing tenant here (idempotent); the
-- store seeds new tenants at publication time (store.Roles.EnsureSystemRoles).
INSERT INTO roles (tenant_id, slug, name, description, is_system)
    SELECT t.id, v.slug, v.name, v.description, true
    FROM tenants t
    CROSS JOIN (VALUES
        ('admin',  'Administrator', 'Full access within the tenant'),
        ('editor', 'Editor',        'Read everything; manage tests, alerts, incidents'),
        ('viewer', 'Viewer',        'Read-only')
    ) AS v(slug, name, description)
ON CONFLICT (tenant_id, slug) DO NOTHING;

-- admin → every permission.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, p.key
    FROM roles r CROSS JOIN permissions p
    WHERE r.slug = 'admin' AND r.is_system
ON CONFLICT (role_id, permission_key) DO NOTHING;

-- viewer → every read permission.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, p.key
    FROM roles r CROSS JOIN permissions p
    WHERE r.slug = 'viewer' AND r.is_system AND p.key LIKE '%.read'
ON CONFLICT (role_id, permission_key) DO NOTHING;

-- editor → read everything + manage tests/alerts/incidents.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, p.key
    FROM roles r CROSS JOIN permissions p
    WHERE r.slug = 'editor' AND r.is_system
      AND (p.key LIKE '%.read' OR p.key IN ('test.write', 'alert.write', 'incident.write'))
ON CONFLICT (role_id, permission_key) DO NOTHING;
