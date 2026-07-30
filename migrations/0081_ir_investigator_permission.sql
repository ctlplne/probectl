-- 0081_ir_investigator_permission.sql — IR-bd73185d: dedicated
-- separation-of-duty permission for encrypted attribution reveal.
--
-- Deliberately do not grant this to admin/editor/viewer. The exact
-- ir-investigator role receives only this permission and gains members through
-- the existing tenant-scoped SCIM group binding surface.

INSERT INTO permissions (key, description) VALUES
    (
        'ir.investigate',
        'Reveal local encrypted IR attribution under audited separation of duty'
    )
ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description;

-- Existing tenants get one dedicated system role. Preserve an operator-created
-- role with the same exact slug if it already exists; the permission grant
-- below makes that role the designated separation-of-duty group.
INSERT INTO roles (tenant_id, slug, name, description, is_system)
SELECT id,
       'ir-investigator',
       'IR Investigator',
       'MFA-bound encrypted incident-response attribution reveal',
       true
  FROM tenants
ON CONFLICT (tenant_id, slug) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_key)
SELECT tenant_id, id, 'ir.investigate'
  FROM roles
 WHERE slug = 'ir-investigator'
ON CONFLICT (role_id, permission_key) DO NOTHING;

-- Existing physical PostgreSQL silos keep tenant-owned RBAC tables in their
-- own schema. LIKE INCLUDING ALL does not copy triggers, so seed those exact
-- routed tables explicitly rather than relying on the pooled trigger below.
DO $seed_silo_ir_investigator$
DECLARE
    tenant record;
    schema_name text;
    role_id uuid;
BEGIN
    FOR tenant IN
        SELECT id
          FROM public.tenants
         WHERE isolation_model = 'siloed'
         ORDER BY id
    LOOP
        schema_name := 't_' || replace(lower(tenant.id::text), '-', '');
        IF to_regclass(format('%I.roles', schema_name)) IS NULL
           OR to_regclass(format('%I.role_permissions', schema_name)) IS NULL THEN
            -- An older/incomplete silo may still rely on public fallback until
            -- the normal startup catch-up creates both routed tables.
            CONTINUE;
        END IF;
        EXECUTE format(
            'INSERT INTO %I.roles
                 (tenant_id, slug, name, description, is_system)
             VALUES ($1, ''ir-investigator'', ''IR Investigator'',
                     ''MFA-bound encrypted incident-response attribution reveal'',
                     true)
             ON CONFLICT (tenant_id, slug) DO NOTHING',
            schema_name
        ) USING tenant.id;
        EXECUTE format(
            'SELECT id FROM %I.roles
              WHERE tenant_id = $1 AND slug = ''ir-investigator''',
            schema_name
        ) INTO role_id USING tenant.id;
        EXECUTE format(
            'INSERT INTO %I.role_permissions
                 (tenant_id, role_id, permission_key)
             VALUES ($1, $2, ''ir.investigate'')
             ON CONFLICT (role_id, permission_key) DO NOTHING',
            schema_name
        ) USING tenant.id, role_id;
    END LOOP;
END
$seed_silo_ir_investigator$;

-- Tenants provisioned after this migration can create the same exact SCIM
-- group. Its role receives only ir.investigate inside the already-established
-- tenant/RLS transaction; arbitrary role names receive nothing.
CREATE OR REPLACE FUNCTION grant_ir_investigator_permission()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.slug = 'ir-investigator' THEN
        INSERT INTO role_permissions (tenant_id, role_id, permission_key)
        VALUES (NEW.tenant_id, NEW.id, 'ir.investigate')
        ON CONFLICT (role_id, permission_key) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS roles_grant_ir_investigator_permission ON roles;
CREATE TRIGGER roles_grant_ir_investigator_permission
AFTER INSERT ON roles
FOR EACH ROW
EXECUTE FUNCTION grant_ir_investigator_permission();
