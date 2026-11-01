-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-2b: reading an import plan and initiating/capturing/applying one are
-- separate tenant permissions. The tenant is resolved before RBAC; these
-- grants never authorize cross-tenant reads or source-selected contexts.
INSERT INTO permissions (key, description) VALUES
    ('nms.import.read', 'Read redacted tenant NMS import plans and provenance'),
    ('nms.import.write', 'Create, review and apply tenant NMS import plans')
ON CONFLICT (key) DO NOTHING;

-- Existing tenants receive the same defaults as Roles.EnsureSystemRoles uses
-- for future tenants: every system role can read, only admin can write.
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'nms.import.read'
    FROM roles r JOIN public.tenants t ON t.id = r.tenant_id
    WHERE r.is_system AND r.slug IN ('admin', 'editor', 'viewer')
      AND t.status IN ('active', 'suspended')
      AND t.audit_write_fenced_at IS NULL
ON CONFLICT (role_id, permission_key) DO NOTHING;
INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'nms.import.write'
    FROM roles r JOIN public.tenants t ON t.id = r.tenant_id
    WHERE r.is_system AND r.slug = 'admin'
      AND t.status IN ('active', 'suspended')
      AND t.audit_write_fenced_at IS NULL
ON CONFLICT (role_id, permission_key) DO NOTHING;
