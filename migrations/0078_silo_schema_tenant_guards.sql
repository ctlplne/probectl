-- 0078_silo_schema_tenant_guards.sql — TENANT-6784d6c9: bind every physical
-- PostgreSQL silo table to the immutable tenant encoded by its schema.
--
-- A GUC-only policy prevents ordinary cross-tenant rows in a pooled table, but
-- it does not prevent tenant A from schema-qualifying tenant B's table and
-- inserting a row labelled A. PostgreSQL also ORs permissive policies, so an
-- unrelated legacy USING(true) policy can bypass a repaired permissive policy.
--
-- Converge only schemas canonically derived from registered siloed tenant UUIDs.
-- Every ordinary table in such a schema must carry a non-null UUID tenant_id.
-- The RESTRICTIVE policy is ANDed with all permissive policies and requires both
-- the caller GUC and the schema's fixed tenant. Existing rows, including
-- contamination, are intentionally not moved, rewritten, or deleted.

DO $silo_schema_tenant_guards$
DECLARE
    silo record;
    tenant_table record;
BEGIN
    FOR silo IN
        SELECT id,
               't_' || replace(lower(id::text), '-', '') AS schema_name
          FROM public.tenants
         WHERE isolation_model = 'siloed'
         ORDER BY id
    LOOP
        IF to_regnamespace(silo.schema_name) IS NULL THEN
            CONTINUE;
        END IF;

        FOR tenant_table IN
            SELECT c.relname AS table_name,
                   a.attname IS NOT NULL AS has_tenant_id,
                   COALESCE(a.atttypid = 'uuid'::regtype, false) AS tenant_id_is_uuid,
                   COALESCE(a.attnotnull, false) AS tenant_id_not_null
              FROM pg_class AS c
              JOIN pg_namespace AS n ON n.oid = c.relnamespace
              LEFT JOIN pg_attribute AS a
                ON a.attrelid = c.oid
               AND a.attname = 'tenant_id'
               AND NOT a.attisdropped
             WHERE n.nspname = silo.schema_name
               AND c.relkind = 'r'
             ORDER BY c.relname
        LOOP
            IF NOT tenant_table.has_tenant_id
               OR NOT tenant_table.tenant_id_is_uuid
               OR NOT tenant_table.tenant_id_not_null THEN
                RAISE EXCEPTION
                    'canonical silo %.% must carry tenant_id uuid NOT NULL',
                    silo.schema_name,
                    tenant_table.table_name;
            END IF;

            EXECUTE format(
                'ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY',
                silo.schema_name,
                tenant_table.table_name
            );
            EXECUTE format(
                'ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY',
                silo.schema_name,
                tenant_table.table_name
            );
            EXECUTE format(
                'DROP POLICY IF EXISTS tenant_isolation ON %I.%I',
                silo.schema_name,
                tenant_table.table_name
            );
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON %I.%I
                   FOR ALL TO PUBLIC
                  USING (
                      tenant_id = %L::uuid
                      AND tenant_id = NULLIF(
                          current_setting(''probectl.tenant_id'', true),
                          ''''
                      )::uuid
                  )
                  WITH CHECK (
                      tenant_id = %L::uuid
                      AND tenant_id = NULLIF(
                          current_setting(''probectl.tenant_id'', true),
                          ''''
                      )::uuid
                  )',
                silo.schema_name,
                tenant_table.table_name,
                silo.id::text,
                silo.id::text
            );
            EXECUTE format(
                'DROP POLICY IF EXISTS tenant_schema_isolation ON %I.%I',
                silo.schema_name,
                tenant_table.table_name
            );
            EXECUTE format(
                'CREATE POLICY tenant_schema_isolation ON %I.%I
                    AS RESTRICTIVE
                   FOR ALL TO PUBLIC
                  USING (
                      tenant_id = %L::uuid
                      AND tenant_id = NULLIF(
                          current_setting(''probectl.tenant_id'', true),
                          ''''
                      )::uuid
                  )
                  WITH CHECK (
                      tenant_id = %L::uuid
                      AND tenant_id = NULLIF(
                          current_setting(''probectl.tenant_id'', true),
                          ''''
                      )::uuid
                  )',
                silo.schema_name,
                tenant_table.table_name,
                silo.id::text,
                silo.id::text
            );
        END LOOP;
    END LOOP;
END
$silo_schema_tenant_guards$;
