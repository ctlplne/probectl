-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Recorded financial terms have their own delegation boundary. Reading
-- telemetry does not imply access to a tenant's agreements or unit rates.
INSERT INTO public.permissions(key,description) VALUES
    ('flow.agreements.read','Read tenant-recorded capacity agreements and financial terms'),
    ('flow.agreements.write','Create, revise and delete tenant-recorded capacity agreements')
ON CONFLICT(key) DO NOTHING;

INSERT INTO public.role_permissions(tenant_id,role_id,permission_key)
 SELECT r.tenant_id,r.id,p.key FROM public.roles r
 JOIN public.tenants t ON t.id=r.tenant_id CROSS JOIN public.permissions p
 WHERE r.slug='admin' AND r.is_system
   AND p.key IN ('flow.agreements.read','flow.agreements.write')
   AND t.status IN ('active','suspended') AND t.audit_write_fenced_at IS NULL
ON CONFLICT(role_id,permission_key) DO NOTHING;

-- Keep repeated broad system-role seeding from granting financial reads.
-- Custom roles and their explicit delegations are untouched.
DELETE FROM public.role_permissions rp USING public.roles r,public.tenants t
 WHERE rp.role_id=r.id AND rp.tenant_id=r.tenant_id AND t.id=r.tenant_id
   AND r.is_system AND r.slug IN ('viewer','editor')
   AND rp.permission_key IN ('flow.agreements.read','flow.agreements.write')
   AND t.status IN ('active','suspended') AND t.audit_write_fenced_at IS NULL;

-- Existing physical silos keep their RBAC rows in the registered tenant
-- schema. Apply the same defaults there, without touching custom role grants.
DO $capacity_agreement_grants$
DECLARE
    tenant record;
    schema_name text;
BEGIN
    FOR tenant IN SELECT id FROM public.tenants
        WHERE status IN ('active','suspended') AND audit_write_fenced_at IS NULL
        ORDER BY id
    LOOP
        schema_name := 't_' || replace(lower(tenant.id::text),'-','');
        IF to_regclass(format('%I.roles',schema_name)) IS NULL
            OR to_regclass(format('%I.role_permissions',schema_name)) IS NULL THEN
            CONTINUE;
        END IF;
        EXECUTE format('INSERT INTO %I.role_permissions(tenant_id,role_id,permission_key)
            SELECT r.tenant_id,r.id,p.key FROM %I.roles r CROSS JOIN public.permissions p
            WHERE r.tenant_id=$1 AND r.is_system AND r.slug=''admin''
              AND p.key IN (''flow.agreements.read'',''flow.agreements.write'')
            ON CONFLICT(role_id,permission_key) DO NOTHING',schema_name,schema_name)
            USING tenant.id;
        EXECUTE format('DELETE FROM %I.role_permissions rp USING %I.roles r
            WHERE rp.tenant_id=$1 AND r.tenant_id=$1 AND rp.role_id=r.id
              AND r.is_system AND r.slug IN (''viewer'',''editor'')
              AND rp.permission_key IN (''flow.agreements.read'',''flow.agreements.write'')',
            schema_name,schema_name) USING tenant.id;
    END LOOP;
END
$capacity_agreement_grants$;
