-- 0076_session_detail_retention.sql
-- Session rows contain email/display-name identity detail. The lifecycle leader
-- now removes absolutely-expired rows and aged authenticated-login predecessor
-- detail under the row's tenant scope. Keep the cleanup tenant-led in the index
-- too, so both pooled RLS and physical-silo execution start at the outer
-- boundary rather than scanning another tenant's rows.

-- Converge databases restored from an older/partial schema ledger before the
-- replacement index references the additive 0072 column.
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS replaced_at timestamptz;

-- lock-ok: sessions is operator-scale control-plane identity state, not an ingestion table; the lifecycle sweep bounds it after this one-time index build
CREATE INDEX IF NOT EXISTS sessions_tenant_expires_cleanup_idx
    ON sessions (tenant_id, expires_at);

-- lock-ok: sessions is operator-scale control-plane identity state, not an ingestion table; the lifecycle sweep bounds it after this one-time index build
CREATE INDEX IF NOT EXISTS sessions_tenant_replaced_cleanup_idx
    ON sessions (tenant_id, replaced_at)
    WHERE replaced_at IS NOT NULL;

-- Existing silo schemas predate this public-table index. LIKE INCLUDING ALL
-- gives new silos both indexes; converge already-provisioned silos here.
-- Schema names come from the tenant UUID/catalog and are quoted as identifiers.
DO $session_cleanup_columns$
DECLARE
    target_schema text;
BEGIN
    FOR target_schema IN
        SELECT s.schema_name
          FROM information_schema.schemata AS s
          JOIN public.tenants AS t
            ON s.schema_name = 't_' || replace(t.id::text, '-', '')
         WHERE t.isolation_model = 'siloed'
           AND EXISTS (
               SELECT 1
                 FROM information_schema.tables AS st
                WHERE st.table_schema = s.schema_name
                  AND st.table_name = 'sessions'
           )
    LOOP
        EXECUTE format(
            'ALTER TABLE %I.sessions
                 ADD COLUMN IF NOT EXISTS replaced_at timestamptz',
            target_schema
        );
    END LOOP;
END
$session_cleanup_columns$;

DO $session_cleanup_indexes$
DECLARE
    target_schema text;
BEGIN
    FOR target_schema IN
        SELECT s.schema_name
          FROM information_schema.schemata AS s
          JOIN public.tenants AS t
            ON s.schema_name = 't_' || replace(t.id::text, '-', '')
         WHERE t.isolation_model = 'siloed'
           AND EXISTS (
               SELECT 1
                 FROM information_schema.tables AS st
                WHERE st.table_schema = s.schema_name
                  AND st.table_name = 'sessions'
           )
    LOOP
        -- lock-ok: each silo sessions table is operator-scale and isolated from other tenants
        EXECUTE format(
            'CREATE INDEX IF NOT EXISTS sessions_tenant_expires_cleanup_idx
                 ON %I.sessions (tenant_id, expires_at)',
            target_schema
        );
        -- lock-ok: each silo sessions table is operator-scale and isolated from other tenants
        EXECUTE format(
            'CREATE INDEX IF NOT EXISTS sessions_tenant_replaced_cleanup_idx
                 ON %I.sessions (tenant_id, replaced_at)
              WHERE replaced_at IS NOT NULL',
            target_schema
        );
    END LOOP;
END
$session_cleanup_indexes$;
