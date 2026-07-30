-- 0075_audit_stream_heads.sql — IR-baec5355: durable audit sequence/hash
-- heads and retention anchors.
--
-- audit_events rows are retention-prunable, so MAX(seq) from that table is not
-- a durable sequence allocator: a full prefix prune made the next append reuse
-- sequence 1, behind an already-advanced SIEM/WORM cursor. A partial prune also
-- removed the hash needed to verify the first retained row.
--
-- These small metadata rows are never touched by audit retention. head_* is
-- advanced atomically with every append; pruned_* records the last deleted
-- event and is advanced atomically with deletion + the append-only prune
-- receipt. Tenant metadata is deployment-global even for a PostgreSQL silo:
-- it contains no audit payload, stays RLS-scoped, and is the durable routing
-- anchor that cannot disappear with a tenant schema's retained row prefix.

CREATE TABLE IF NOT EXISTS audit_stream_heads (
    tenant_id    uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    head_seq     bigint NOT NULL DEFAULT 0 CHECK (head_seq >= 0),
    head_hash    text NOT NULL DEFAULT '',
    pruned_seq   bigint NOT NULL DEFAULT 0 CHECK (pruned_seq >= 0),
    pruned_hash  text NOT NULL DEFAULT '',
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (pruned_seq <= head_seq),
    CHECK ((head_seq = 0) = (head_hash = '')),
    CHECK ((pruned_seq = 0) = (pruned_hash = ''))
);

CREATE TABLE IF NOT EXISTS provider_audit_stream_head (
    singleton    boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    head_seq     bigint NOT NULL DEFAULT 0 CHECK (head_seq >= 0),
    head_hash    text NOT NULL DEFAULT '',
    pruned_seq   bigint NOT NULL DEFAULT 0 CHECK (pruned_seq >= 0),
    pruned_hash  text NOT NULL DEFAULT '',
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (pruned_seq <= head_seq),
    CHECK ((head_seq = 0) = (head_hash = '')),
    CHECK ((pruned_seq = 0) = (pruned_hash = ''))
);

-- Keep RLS forced even during a replay/partial-run recovery. Temporary
-- SELECT/INSERT-only policies are scoped by the same tenant GUC as runtime
-- access (ON CONFLICT needs both commands). They are removed before commit, so
-- no role receives a durable migration capability.
ALTER TABLE audit_stream_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_stream_heads FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_stream_head_migration_read ON audit_stream_heads;
DROP POLICY IF EXISTS audit_stream_head_migration_backfill ON audit_stream_heads;
CREATE POLICY audit_stream_head_migration_read ON audit_stream_heads
    FOR SELECT
    USING (
        tenant_id = NULLIF(
            current_setting('probectl.tenant_id', true),
            ''
        )::uuid
    );
CREATE POLICY audit_stream_head_migration_backfill ON audit_stream_heads
    FOR INSERT
    WITH CHECK (
        tenant_id = NULLIF(
            current_setting('probectl.tenant_id', true),
            ''
        )::uuid
    );

INSERT INTO provider_audit_stream_head
    (singleton, head_seq, head_hash, pruned_seq, pruned_hash)
SELECT true,
       last_row.seq,
       last_row.hash,
       CASE WHEN first_row.seq > 1 THEN first_row.seq - 1 ELSE 0 END,
       CASE WHEN first_row.seq > 1 THEN first_row.prev_hash ELSE '' END
  FROM LATERAL (
      SELECT seq, prev_hash
        FROM provider_audit_events
       ORDER BY seq
       LIMIT 1
  ) AS first_row
 CROSS JOIN LATERAL (
      SELECT seq, hash
        FROM provider_audit_events
       ORDER BY seq DESC
       LIMIT 1
  ) AS last_row
ON CONFLICT (singleton) DO NOTHING;

-- 0045 left the provider DELETE policy broad and relied on an explicit WHERE.
-- Retention also uses this capability, so bind DELETE itself to the same
-- tenant GUC as SELECT. Tenant-lifecycle already sets this GUC before erasure.
DROP POLICY IF EXISTS provider_audit_erase ON audit_events;
CREATE POLICY provider_audit_erase ON audit_events
    FOR DELETE TO probectl_provider
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

-- Backfill every tenant stream under that tenant's own RLS setting. This is
-- required even for the table owner: audit_events has FORCE ROW LEVEL SECURITY,
-- and the supported migration role is NOSUPERUSER/NOBYPASSRLS. Silo streams
-- are read from their routed schemas, never from stale/misrouted public rows.
--
-- Existing PostgreSQL silos cloned audit_events before the provider retention
-- capability existed, and the old generic provisioner grant also gave the app
-- role DELETE. Repair every registered silo in place before reading it. Future
-- silos receive the same least-privilege recipe from ee/silo's provision plan.
DO $$
DECLARE
    tenant_stream record;
    silo record;
    previous_tenant text := current_setting('probectl.tenant_id', true);
BEGIN
    FOR tenant_stream IN
        SELECT id::text AS tenant_id
          FROM tenants
         WHERE isolation_model <> 'siloed'
    LOOP
        PERFORM set_config(
            'probectl.tenant_id',
            tenant_stream.tenant_id,
            true
        );

        -- When the first retained row is above sequence 1, prev_hash is the
        -- exact retention anchor for first_seq-1. The two indexed LIMIT reads
        -- avoid aggregating an unbounded history in memory.
        BEGIN
            -- Plan each scoped read/insert after this iteration's tenant GUC
            -- is bound; no statement spans two tenant settings.
            EXECUTE $pooled_backfill$
                INSERT INTO public.audit_stream_heads
                    (tenant_id, head_seq, head_hash, pruned_seq, pruned_hash)
                SELECT last_row.tenant_id,
                       last_row.seq,
                       last_row.hash,
                       CASE WHEN first_row.seq > 1
                            THEN first_row.seq - 1 ELSE 0 END,
                       CASE WHEN first_row.seq > 1
                            THEN first_row.prev_hash ELSE '' END
                  FROM LATERAL (
                      SELECT seq, prev_hash
                        FROM public.audit_events
                       WHERE tenant_id = $1
                       ORDER BY seq
                       LIMIT 1
                  ) AS first_row
                 CROSS JOIN LATERAL (
                      SELECT tenant_id, seq, hash
                        FROM public.audit_events
                       WHERE tenant_id = $1
                       ORDER BY seq DESC
                       LIMIT 1
                  ) AS last_row
                ON CONFLICT (tenant_id) DO NOTHING
            $pooled_backfill$
            USING tenant_stream.tenant_id::uuid;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE EXCEPTION
                    'pooled audit head backfill denied: tenant=%, guc=%',
                    tenant_stream.tenant_id,
                    current_setting('probectl.tenant_id', true)
                    USING ERRCODE = '42501';
        END;
    END LOOP;

    FOR silo IN
        SELECT id::text AS tenant_id,
               't_' || replace(id::text, '-', '') AS schema_name
          FROM tenants
         WHERE isolation_model = 'siloed'
    LOOP
        IF to_regclass(format('%I.audit_events', silo.schema_name)) IS NULL THEN
            CONTINUE;
        END IF;

        PERFORM set_config('probectl.tenant_id', silo.tenant_id, true);
        EXECUTE format(
            'GRANT USAGE ON SCHEMA %I TO probectl_provider',
            silo.schema_name
        );
        EXECUTE format(
            'ALTER TABLE %I.audit_events ENABLE ROW LEVEL SECURITY',
            silo.schema_name
        );
        EXECUTE format(
            'ALTER TABLE %I.audit_events FORCE ROW LEVEL SECURITY',
            silo.schema_name
        );
        EXECUTE format(
            'DROP POLICY IF EXISTS tenant_isolation ON %I.audit_events',
            silo.schema_name
        );
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I.audit_events
               USING (tenant_id = NULLIF(current_setting(''probectl.tenant_id'', true), '''')::uuid)
               WITH CHECK (tenant_id = NULLIF(current_setting(''probectl.tenant_id'', true), '''')::uuid)',
            silo.schema_name
        );
        EXECUTE format(
            'REVOKE ALL ON %I.audit_events FROM probectl_app',
            silo.schema_name
        );
        EXECUTE format(
            'GRANT SELECT, INSERT ON %I.audit_events TO probectl_app',
            silo.schema_name
        );
        EXECUTE format(
            'REVOKE ALL ON %I.audit_events FROM probectl_provider',
            silo.schema_name
        );
        EXECUTE format(
            'GRANT SELECT, DELETE ON %I.audit_events TO probectl_provider',
            silo.schema_name
        );

        -- A fully-pruned legacy stream has no locally recoverable hash and is
        -- handled fail-closed at runtime against its silo-local SIEM cursor.
        EXECUTE format(
            $backfill$
            WITH first_row AS (
                SELECT seq, prev_hash
                  FROM %I.audit_events
                 WHERE tenant_id = %L::uuid
                 ORDER BY seq
                 LIMIT 1
            ),
            last_row AS (
                SELECT tenant_id, seq, hash
                  FROM %I.audit_events
                 WHERE tenant_id = %L::uuid
                 ORDER BY seq DESC
                 LIMIT 1
            )
            INSERT INTO public.audit_stream_heads
                (tenant_id, head_seq, head_hash, pruned_seq, pruned_hash)
            SELECT l.tenant_id,
                   l.seq,
                   l.hash,
                   CASE WHEN f.seq > 1 THEN f.seq - 1 ELSE 0 END,
                   CASE WHEN f.seq > 1 THEN f.prev_hash ELSE '' END
              FROM last_row AS l
              CROSS JOIN first_row AS f
            ON CONFLICT (tenant_id) DO NOTHING
            $backfill$,
            silo.schema_name,
            silo.tenant_id,
            silo.schema_name,
            silo.tenant_id
        );
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
$$;

-- Remove the narrowly-scoped migration capability before installing the
-- runtime policies. The app may advance but not delete heads; lifecycle
-- erasure uses the separately-scoped provider policy.
DROP POLICY IF EXISTS audit_stream_head_migration_read ON audit_stream_heads;
DROP POLICY IF EXISTS audit_stream_head_migration_backfill ON audit_stream_heads;
ALTER TABLE audit_stream_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_stream_heads FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_stream_head_tenant ON audit_stream_heads;
CREATE POLICY audit_stream_head_tenant ON audit_stream_heads
    FOR ALL TO probectl_app
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS provider_audit_stream_head_erase ON audit_stream_heads;
DROP POLICY IF EXISTS provider_audit_stream_head_verify ON audit_stream_heads;
DROP POLICY IF EXISTS provider_audit_stream_head_read ON audit_stream_heads;
CREATE POLICY provider_audit_stream_head_read ON audit_stream_heads
    FOR SELECT TO probectl_provider
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS provider_audit_stream_head_insert ON audit_stream_heads;
CREATE POLICY provider_audit_stream_head_insert ON audit_stream_heads
    FOR INSERT TO probectl_provider
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS provider_audit_stream_head_update ON audit_stream_heads;
CREATE POLICY provider_audit_stream_head_update ON audit_stream_heads
    FOR UPDATE TO probectl_provider
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

-- 0007's default privilege grants include DELETE; narrow this append metadata
-- back to its intentional least-privilege shape.
REVOKE ALL ON audit_stream_heads FROM probectl_app;
GRANT SELECT, INSERT, UPDATE ON audit_stream_heads TO probectl_app;
REVOKE ALL ON audit_stream_heads FROM probectl_provider;
GRANT SELECT, INSERT, UPDATE ON audit_stream_heads TO probectl_provider;

-- Provider stream appends run only as the dedicated provider role.
REVOKE ALL ON provider_audit_stream_head FROM probectl_app;
REVOKE ALL ON provider_audit_stream_head FROM probectl_provider;
GRANT SELECT, INSERT, UPDATE ON provider_audit_stream_head TO probectl_provider;
