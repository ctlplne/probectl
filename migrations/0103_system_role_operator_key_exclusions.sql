-- SPDX-License-Identifier: BUSL-1.1
--
-- AUTHZ-07 / AUTHZ-09: migration 0094 (and the old EnsureSystemRoles) granted
-- the admin role every permission — including ir.investigate, which 0081
-- deliberately reserves for the dedicated ir-investigator role — and granted
-- viewer/editor every '%.read' key, including the operator/provider-
-- infrastructure reads diagnostics.read and fairness.read. On a shared MSP
-- control plane that exposed deployment-global config, the license record, and
-- SIEM/secrets health to every tenant's read-only users, and broke the IR
-- attribution separation of duty.
--
-- Remove those over-granted rows from existing deployments (idempotent). The
-- store's EnsureSystemRoles now excludes the same keys when seeding new tenants.

-- Pooled tenants (RLS-scoped rows in the shared tables).
DELETE FROM role_permissions rp
    USING roles r
    WHERE rp.role_id = r.id
      AND r.is_system
      AND (
            (r.slug = 'admin'               AND rp.permission_key IN ('ir.investigate'))
         OR (r.slug IN ('viewer', 'editor') AND rp.permission_key IN ('diagnostics.read', 'fairness.read'))
          );

-- Physically-siloed tenants keep RBAC tables in their own schema; 0081 showed
-- LIKE INCLUDING ALL does not copy triggers, so correct each routed table here.
DO $authz0709_silo$
DECLARE
    tenant record;
    schema_name text;
BEGIN
    FOR tenant IN
        SELECT id
          FROM public.tenants
         WHERE isolation_model = 'siloed'
         ORDER BY id
    LOOP
        schema_name := 't_' || replace(lower(tenant.id::text), '-', '');
        IF to_regclass(format('%I.role_permissions', schema_name)) IS NULL
           OR to_regclass(format('%I.roles', schema_name)) IS NULL THEN
            CONTINUE;
        END IF;
        EXECUTE format(
            'DELETE FROM %I.role_permissions rp
                 USING %I.roles r
                 WHERE rp.role_id = r.id
                   AND r.is_system
                   AND (
                         (r.slug = ''admin''               AND rp.permission_key IN (''ir.investigate''))
                      OR (r.slug IN (''viewer'', ''editor'') AND rp.permission_key IN (''diagnostics.read'', ''fairness.read''))
                       )',
            schema_name, schema_name
        );
    END LOOP;
END
$authz0709_silo$;
