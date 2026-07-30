-- 0077_audit_subject_erasures.sql — DATA-85020084: durable, tenant-routed
-- subject-erasure projection state.
--
-- privacy.subject_erase remains an immutable audit event, but an event row is
-- not a durable projection index once normal audit retention can remove an
-- exported prefix. Keep only the tenant-scoped one-way subject hash here. The
-- app and retention roles may append projection facts; neither may rewrite
-- them. The provider role may delete them only for verified full-tenant erase.

CREATE TABLE IF NOT EXISTS audit_subject_erasures (
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_hash text NOT NULL
        CHECK (subject_hash ~ '^[0-9a-f]{64}$'),
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject_hash)
);

ALTER TABLE audit_subject_erasures ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_subject_erasures FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_subject_erasure_select ON audit_subject_erasures;
CREATE POLICY audit_subject_erasure_select ON audit_subject_erasures
    FOR SELECT TO probectl_app, probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );

DROP POLICY IF EXISTS audit_subject_erasure_insert ON audit_subject_erasures;
CREATE POLICY audit_subject_erasure_insert ON audit_subject_erasures
    FOR INSERT TO probectl_app, probectl_provider
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );

DROP POLICY IF EXISTS audit_subject_erasure_delete ON audit_subject_erasures;
CREATE POLICY audit_subject_erasure_delete ON audit_subject_erasures
    FOR DELETE TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );

-- 0007's default privileges grant ordinary tenant tables full DML. Projection
-- state is append-only until full tenant erasure, so narrow both roles.
REVOKE ALL ON audit_subject_erasures FROM probectl_app;
GRANT SELECT, INSERT ON audit_subject_erasures TO probectl_app;
REVOKE ALL ON audit_subject_erasures FROM probectl_provider;
GRANT SELECT, INSERT, DELETE ON audit_subject_erasures TO probectl_provider;

-- The supported migration owner is NOSUPERUSER/NOBYPASSRLS and is not
-- required to be a member of either runtime role. Give that owner one
-- migration-lifetime INSERT and conflict-detection SELECT policies, both still
-- bound to the tenant GUC.
-- It is removed immediately after backfill and a migration failure rolls the
-- entire policy creation back.
DROP POLICY IF EXISTS audit_subject_erasure_migration_insert
    ON audit_subject_erasures;
CREATE POLICY audit_subject_erasure_migration_insert
    ON audit_subject_erasures
    FOR INSERT
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS audit_subject_erasure_migration_read
    ON audit_subject_erasures;
CREATE POLICY audit_subject_erasure_migration_read
    ON audit_subject_erasures
    FOR SELECT
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );

-- Converge every already-provisioned silo. New and catch-up silos use the same
-- special least-privilege recipe in ee/silo's planner.
DO $audit_subject_erasure_silos$
DECLARE
    silo record;
BEGIN
    FOR silo IN
        SELECT id,
               't_' || replace(id::text, '-', '') AS schema_name
          FROM tenants
         WHERE isolation_model = 'siloed'
    LOOP
        IF NOT EXISTS (
            SELECT 1
              FROM information_schema.schemata
             WHERE schema_name = silo.schema_name
        ) THEN
            CONTINUE;
        END IF;

        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I.audit_subject_erasures
                 (LIKE public.audit_subject_erasures INCLUDING ALL)',
            silo.schema_name
        );
        EXECUTE format(
            'ALTER TABLE %I.audit_subject_erasures ENABLE ROW LEVEL SECURITY',
            silo.schema_name
        );
        EXECUTE format(
            'ALTER TABLE %I.audit_subject_erasures FORCE ROW LEVEL SECURITY',
            silo.schema_name
        );
        EXECUTE format(
            'DROP POLICY IF EXISTS tenant_isolation
                 ON %I.audit_subject_erasures',
            silo.schema_name
        );
        EXECUTE format(
            'CREATE POLICY tenant_isolation
                 ON %I.audit_subject_erasures
              USING (
                  tenant_id = %L::uuid
                  AND tenant_id =
                      NULLIF(current_setting(''probectl.tenant_id'', true), '''')::uuid
              )
              WITH CHECK (
                  tenant_id = %L::uuid
                  AND tenant_id =
                      NULLIF(current_setting(''probectl.tenant_id'', true), '''')::uuid
              )',
            silo.schema_name,
            silo.id,
            silo.id
        );
        -- A permissive GUC-only policy can be OR-combined with another
        -- permissive policy. Add an immutable schema-owner fence as
        -- RESTRICTIVE so a qualified access to tenant B's physical table can
        -- never admit tenant A rows, even if a future policy is too broad.
        EXECUTE format(
            'DROP POLICY IF EXISTS tenant_schema_isolation
                 ON %I.audit_subject_erasures',
            silo.schema_name
        );
        EXECUTE format(
            'CREATE POLICY tenant_schema_isolation
                 ON %I.audit_subject_erasures
                 AS RESTRICTIVE
                 FOR ALL
                 TO PUBLIC
              USING (
                  tenant_id = %L::uuid
                  AND tenant_id =
                      NULLIF(current_setting(''probectl.tenant_id'', true), '''')::uuid
              )
              WITH CHECK (
                  tenant_id = %L::uuid
                  AND tenant_id =
                      NULLIF(current_setting(''probectl.tenant_id'', true), '''')::uuid
              )',
            silo.schema_name,
            silo.id,
            silo.id
        );
        EXECUTE format(
            'GRANT USAGE ON SCHEMA %I TO probectl_provider',
            silo.schema_name
        );
        EXECUTE format(
            'REVOKE ALL ON %I.audit_subject_erasures FROM probectl_app',
            silo.schema_name
        );
        EXECUTE format(
            'GRANT SELECT, INSERT
                 ON %I.audit_subject_erasures TO probectl_app',
            silo.schema_name
        );
        EXECUTE format(
            'REVOKE ALL ON %I.audit_subject_erasures FROM probectl_provider',
            silo.schema_name
        );
        EXECUTE format(
            'GRANT SELECT, INSERT, DELETE
                 ON %I.audit_subject_erasures TO probectl_provider',
            silo.schema_name
        );
    END LOOP;
END
$audit_subject_erasure_silos$;

-- Backfill through the supported NOBYPASSRLS migration-owner model. Existing
-- audit source policies and the temporary target policies remain FORCE-RLS
-- constrained; each read/write gets the tenant GUC before touching pooled or
-- silo storage.
DO $audit_subject_erasure_backfill$
DECLARE
    tenant record;
    source_table text;
    target_table text;
    malformed bigint;
    previous_tenant text := current_setting('probectl.tenant_id', true);
BEGIN
    FOR tenant IN
        SELECT id,
               isolation_model,
               't_' || replace(id::text, '-', '') AS schema_name
          FROM public.tenants
         ORDER BY id
    LOOP
        PERFORM set_config('probectl.tenant_id', tenant.id::text, true);

        IF tenant.isolation_model = 'siloed' THEN
            IF to_regclass(
                format('%I.audit_events', tenant.schema_name)
            ) IS NULL OR to_regclass(
                format('%I.audit_subject_erasures', tenant.schema_name)
            ) IS NULL THEN
                CONTINUE;
            END IF;
            source_table := format('%I.audit_events', tenant.schema_name);
            target_table := format(
                '%I.audit_subject_erasures',
                tenant.schema_name
            );
        ELSE
            source_table := 'public.audit_events';
            target_table := 'public.audit_subject_erasures';
        END IF;

        EXECUTE format(
            'SELECT count(*)
               FROM %s
              WHERE tenant_id = $1::uuid
                AND action = $2
                AND (
                    data->>''subject_hash'' IS NULL
                    OR data->>''subject_hash'' !~ ''^[0-9a-f]{64}$''
                )',
            source_table
        )
        INTO malformed
        USING tenant.id, 'privacy.subject_erase';
        IF malformed <> 0 THEN
            RAISE EXCEPTION
                'tenant % has % malformed privacy.subject_erase markers',
                tenant.id,
                malformed;
        END IF;

        BEGIN
            EXECUTE format(
                'INSERT INTO %s (tenant_id, subject_hash, created_at)
                 SELECT tenant_id,
                        data->>''subject_hash'',
                        min(created_at)
                   FROM %s
                  WHERE tenant_id = $1::uuid
                    AND action = $2
                  GROUP BY tenant_id, data->>''subject_hash''
                 ON CONFLICT (tenant_id, subject_hash) DO NOTHING',
                target_table,
                source_table
            )
            USING tenant.id, 'privacy.subject_erase';
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE EXCEPTION
                    'subject-erasure projection backfill denied: tenant=%, source=%, target=%, guc=%, role=%',
                    tenant.id,
                    source_table,
                    target_table,
                    current_setting('probectl.tenant_id', true),
                    current_user
                    USING ERRCODE = '42501';
        END;
    END LOOP;

    PERFORM set_config(
        'probectl.tenant_id',
        COALESCE(previous_tenant, ''),
        true
    );
EXCEPTION
    WHEN OTHERS THEN
        PERFORM set_config(
            'probectl.tenant_id',
            COALESCE(previous_tenant, ''),
            true
        );
        RAISE;
END
$audit_subject_erasure_backfill$;

DROP POLICY IF EXISTS audit_subject_erasure_migration_insert
    ON audit_subject_erasures;
DROP POLICY IF EXISTS audit_subject_erasure_migration_read
    ON audit_subject_erasures;
