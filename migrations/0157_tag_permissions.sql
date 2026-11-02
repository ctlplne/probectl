-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-3: tag metadata uses its own tenant permissions. Tenant auth and FORCE
-- RLS precede these RBAC checks on every API, CLI, UI and MCP path.
INSERT INTO permissions (key, description) VALUES
    ('tags.read', 'Read tenant tag definitions, current values and provenance'),
    ('tags.write', 'Create, change and remove tenant tag definitions, rules and assignments')
ON CONFLICT (key) DO NOTHING;

-- Existing active/suspended tenants receive the same defaults as future
-- tenants seeded by Roles.EnsureSystemRoles. No operator/provider read grant.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'tags.read'
    FROM roles r JOIN public.tenants t ON t.id = r.tenant_id
    WHERE r.is_system AND r.slug IN ('admin', 'editor', 'viewer')
      AND t.status IN ('active', 'suspended')
      AND t.audit_write_fenced_at IS NULL
ON CONFLICT (role_id, permission_key) DO NOTHING;
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'tags.write'
    FROM roles r JOIN public.tenants t ON t.id = r.tenant_id
    WHERE r.is_system AND r.slug = 'admin'
      AND t.status IN ('active', 'suspended')
      AND t.audit_write_fenced_at IS NULL
ON CONFLICT (role_id, permission_key) DO NOTHING;
