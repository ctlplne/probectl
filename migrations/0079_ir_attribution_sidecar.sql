-- 0079_ir_attribution_sidecar.sql — IR-3f573c58: encrypted, local-only
-- provider break-glass attribution staging.
--
-- Plaintext operator/tenant/grant/consent/outcome data never enters these
-- columns. The Go writer seals it through internal/crypto under an
-- operator-owned public wrapping key, then hash-chains and signs the opaque
-- record in the same transaction as provider_audit_events.
--
-- This migration intentionally establishes only the append-time inner
-- envelope. A later migration binds that opaque envelope to the exact signed
-- WORM segment and advances an independent retention watermark. Until that
-- binding exists, provider pruning fails closed in the retention runner.

CREATE TABLE IF NOT EXISTS public.ir_attribution_records (
    tenant_id   uuid NOT NULL
                    REFERENCES public.tenants(id) ON DELETE RESTRICT,
    audit_seq   bigint NOT NULL CHECK (audit_seq > 0),
    chain_pos   bigint NOT NULL CHECK (chain_pos > 0),
    event_ref   text NOT NULL CHECK (event_ref ~ '^[0-9a-f]{64}$'),
    key_id      text NOT NULL
                    CHECK (octet_length(key_id) BETWEEN 1 AND 256),
    wrapped_dek bytea NOT NULL
                    CHECK (octet_length(wrapped_dek) BETWEEN 1 AND 4096),
    ciphertext  bytea NOT NULL
                    CHECK (octet_length(ciphertext) BETWEEN 1 AND 32768),
    prev_hash   text NOT NULL
                    CHECK (prev_hash = '' OR prev_hash ~ '^[0-9a-f]{64}$'),
    hash        text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    signature   bytea NOT NULL CHECK (octet_length(signature) = 64),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, audit_seq),
    UNIQUE (tenant_id, chain_pos),
    UNIQUE (tenant_id, event_ref)
);
CREATE INDEX IF NOT EXISTS ir_attribution_records_tenant_seq_idx
    ON public.ir_attribution_records (tenant_id, audit_seq);

-- The signed head is deliberately public control metadata even for a siloed
-- tenant. It contains no attribution or ciphertext, and gives startup/verify
-- one durable tail anchor with which to detect record removal.
CREATE TABLE IF NOT EXISTS public.ir_attribution_heads (
    tenant_id      uuid PRIMARY KEY
                        REFERENCES public.tenants(id) ON DELETE RESTRICT,
    record_count   bigint NOT NULL DEFAULT 0 CHECK (record_count >= 0),
    last_audit_seq bigint NOT NULL DEFAULT 0 CHECK (last_audit_seq >= 0),
    last_hash      text NOT NULL DEFAULT '',
    head_signature bytea NOT NULL DEFAULT ''::bytea,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (
            record_count = 0
            AND last_audit_seq = 0
            AND last_hash = ''
            AND octet_length(head_signature) = 0
        )
        OR
        (
            record_count > 0
            AND last_audit_seq > 0
            AND last_hash ~ '^[0-9a-f]{64}$'
            AND octet_length(head_signature) = 64
        )
    )
);

ALTER TABLE public.ir_attribution_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ir_attribution_records FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ir_attribution_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ir_attribution_heads FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ir_attribution_record_select
    ON public.ir_attribution_records;
CREATE POLICY ir_attribution_record_select
    ON public.ir_attribution_records
    FOR SELECT TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );

DROP POLICY IF EXISTS ir_attribution_record_insert
    ON public.ir_attribution_records;
CREATE POLICY ir_attribution_record_insert
    ON public.ir_attribution_records
    FOR INSERT TO probectl_provider
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );

-- A siloed tenant can never fall back into the pooled public table even if a
-- caller deliberately sets that tenant's GUC and schema-qualifies public.
DROP POLICY IF EXISTS ir_attribution_record_public_route
    ON public.ir_attribution_records;
CREATE POLICY ir_attribution_record_public_route
    ON public.ir_attribution_records
    AS RESTRICTIVE
    FOR ALL TO probectl_provider
    USING (
        EXISTS (
            SELECT 1
              FROM public.tenants
             WHERE id = ir_attribution_records.tenant_id
               AND isolation_model IN ('pooled', 'hybrid')
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1
              FROM public.tenants
             WHERE id = ir_attribution_records.tenant_id
               AND isolation_model IN ('pooled', 'hybrid')
        )
    );

DROP POLICY IF EXISTS ir_attribution_head_select
    ON public.ir_attribution_heads;
CREATE POLICY ir_attribution_head_select
    ON public.ir_attribution_heads
    FOR SELECT TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_attribution_head_insert
    ON public.ir_attribution_heads;
CREATE POLICY ir_attribution_head_insert
    ON public.ir_attribution_heads
    FOR INSERT TO probectl_provider
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_attribution_head_update
    ON public.ir_attribution_heads;
CREATE POLICY ir_attribution_head_update
    ON public.ir_attribution_heads
    FOR UPDATE TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );

REVOKE ALL ON public.ir_attribution_records
    FROM PUBLIC, probectl_app, probectl_provider;
GRANT SELECT, INSERT ON public.ir_attribution_records TO probectl_provider;
REVOKE ALL ON public.ir_attribution_heads
    FROM PUBLIC, probectl_app, probectl_provider;
GRANT SELECT, INSERT, UPDATE ON public.ir_attribution_heads
    TO probectl_provider;

-- Converge every already-provisioned PostgreSQL silo. New/restored silos use
-- the same recipe in ee/silo's planner.
DO $ir_attribution_existing_silos$
DECLARE
    tenant record;
    schema_name text;
BEGIN
    FOR tenant IN
        SELECT id
          FROM public.tenants
         WHERE isolation_model = 'siloed'
    LOOP
        schema_name := 't_' || replace(tenant.id::text, '-', '');
        IF to_regnamespace(schema_name) IS NULL THEN
            CONTINUE;
        END IF;

        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I.ir_attribution_records
                 (LIKE public.ir_attribution_records INCLUDING ALL)',
            schema_name
        );
        EXECUTE format(
            'ALTER TABLE %I.ir_attribution_records ENABLE ROW LEVEL SECURITY',
            schema_name
        );
        EXECUTE format(
            'ALTER TABLE %I.ir_attribution_records FORCE ROW LEVEL SECURITY',
            schema_name
        );
        EXECUTE format(
            'DROP POLICY IF EXISTS tenant_isolation
                 ON %I.ir_attribution_records',
            schema_name
        );
        EXECUTE format(
            'CREATE POLICY tenant_isolation
                 ON %I.ir_attribution_records
                 FOR ALL TO probectl_provider
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
            schema_name,
            tenant.id,
            tenant.id
        );
        EXECUTE format(
            'DROP POLICY IF EXISTS tenant_schema_isolation
                 ON %I.ir_attribution_records',
            schema_name
        );
        EXECUTE format(
            'CREATE POLICY tenant_schema_isolation
                 ON %I.ir_attribution_records
                 AS RESTRICTIVE
                 FOR ALL TO PUBLIC
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
            schema_name,
            tenant.id,
            tenant.id
        );
        EXECUTE format(
            'GRANT USAGE ON SCHEMA %I TO probectl_provider',
            schema_name
        );
        EXECUTE format(
            'REVOKE ALL ON %I.ir_attribution_records
                 FROM PUBLIC, probectl_app, probectl_provider',
            schema_name
        );
        EXECUTE format(
            'GRANT SELECT, INSERT ON %I.ir_attribution_records
                 TO probectl_provider',
            schema_name
        );
    END LOOP;
END
$ir_attribution_existing_silos$;
