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

-- Backfill live and previously partially-pruned pooled streams. Silo streams
-- are read from their routed schemas below, never from stale/misrouted public
-- rows. When the first retained row is above sequence 1, its prev_hash is the
-- exact retention anchor for first_seq-1. DISTINCT ON uses the existing
-- tenant/sequence index and avoids aggregating an unbounded history in memory.
WITH first_rows AS (
    SELECT DISTINCT ON (tenant_id)
           tenant_id, seq, prev_hash
      FROM audit_events
     ORDER BY tenant_id, seq
),
last_rows AS (
    SELECT DISTINCT ON (tenant_id)
           tenant_id, seq, hash
      FROM audit_events
     ORDER BY tenant_id, seq DESC
)
INSERT INTO audit_stream_heads
    (tenant_id, head_seq, head_hash, pruned_seq, pruned_hash)
SELECT l.tenant_id,
       l.seq,
       l.hash,
       CASE WHEN f.seq > 1 THEN f.seq - 1 ELSE 0 END,
       CASE WHEN f.seq > 1 THEN f.prev_hash ELSE '' END
  FROM last_rows AS l
  JOIN first_rows AS f USING (tenant_id)
  JOIN tenants AS t ON t.id = l.tenant_id
 WHERE t.isolation_model <> 'siloed'
ON CONFLICT (tenant_id) DO NOTHING;

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

-- Tenant heads are scoped at the storage layer. The app may advance but not
-- delete them; lifecycle erasure uses the separately-scoped provider policy.
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

-- 0045 left the provider DELETE policy broad and relied on an explicit WHERE.
-- Retention also uses this capability, so bind DELETE itself to the same
-- tenant GUC as SELECT. Tenant-lifecycle already sets this GUC before erasure.
DROP POLICY IF EXISTS provider_audit_erase ON audit_events;
CREATE POLICY provider_audit_erase ON audit_events
    FOR DELETE TO probectl_provider
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

-- Existing PostgreSQL silos cloned audit_events before the provider retention
-- capability existed, and the old generic provisioner grant also gave the app
-- role DELETE. Repair every registered silo in place. Future silos receive the
-- same least-privilege grants from ee/silo's provision plan.
DO $$
DECLARE
    silo record;
BEGIN
    FOR silo IN
        SELECT id::text AS tenant_id,
               't_' || replace(id::text, '-', '') AS schema_name
          FROM tenants
         WHERE isolation_model = 'siloed'
    LOOP
        IF to_regclass(format('%I.audit_events', silo.schema_name)) IS NULL THEN
            CONTINUE;
        END IF;

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

        -- Static SQL above backfills pooled streams. Backfill each live silo
        -- from its physical table as well; a fully-pruned legacy stream still
        -- has no locally recoverable hash and is handled fail-closed at runtime
        -- against its silo-local SIEM cursor.
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
END
$$;

-- Provider stream appends run only as the dedicated provider role.
REVOKE ALL ON provider_audit_stream_head FROM probectl_app;
REVOKE ALL ON provider_audit_stream_head FROM probectl_provider;
GRANT SELECT, INSERT, UPDATE ON provider_audit_stream_head TO probectl_provider;
