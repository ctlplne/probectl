-- 0084_ir_post_shred_attempts.sql — IR-3aa04f13: retain signed,
-- non-attributing receipts for denied IR reveals after crypto-shred.
--
-- This is provider-control evidence ABOUT a deleted tenant, not recoverable
-- tenant IR attribution. It survives silo teardown and ordinary tenant-data
-- erasure, is scoped through the provider role by target tenant, and contains
-- only the provider operator, attempt time, fixed reveal surface/outcome, and
-- the provider-stream event hash. In particular it contains no requested IR
-- event, grant, consent, reason, sidecar ciphertext, wrapped key, or key
-- location. The independent signed head makes removal and reordering visible.

CREATE TABLE IF NOT EXISTS public.ir_post_shred_attempt_records (
    tenant_id          uuid NOT NULL,
    chain_pos          bigint NOT NULL CHECK (chain_pos > 0),
    attempt_at         timestamptz NOT NULL,
    operator           text NOT NULL
                            CHECK (octet_length(operator) BETWEEN 1 AND 320),
    surface            text NOT NULL CHECK (surface = 'audit.ir.reveal'),
    outcome            text NOT NULL CHECK (outcome = 'denied-post-shred'),
    provider_event_ref text NOT NULL
                            CHECK (provider_event_ref ~ '^[0-9a-f]{64}$'),
    prev_hash          text NOT NULL
                            CHECK (
                                prev_hash = ''
                                OR prev_hash ~ '^[0-9a-f]{64}$'
                            ),
    hash               text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    signature          bytea NOT NULL CHECK (octet_length(signature) = 64),
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, chain_pos),
    UNIQUE (tenant_id, provider_event_ref),
    UNIQUE (tenant_id, hash)
);

CREATE INDEX IF NOT EXISTS ir_post_shred_attempt_records_tenant_time_idx
    ON public.ir_post_shred_attempt_records (tenant_id, attempt_at DESC);

CREATE TABLE IF NOT EXISTS public.ir_post_shred_attempt_heads (
    tenant_id      uuid PRIMARY KEY,
    record_count   bigint NOT NULL DEFAULT 0 CHECK (record_count >= 0),
    last_hash      text NOT NULL DEFAULT '',
    head_signature bytea NOT NULL DEFAULT ''::bytea,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (
            record_count = 0
            AND last_hash = ''
            AND octet_length(head_signature) = 0
        )
        OR
        (
            record_count > 0
            AND last_hash ~ '^[0-9a-f]{64}$'
            AND octet_length(head_signature) = 64
        )
    )
);

ALTER TABLE public.ir_post_shred_attempt_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ir_post_shred_attempt_records FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ir_post_shred_attempt_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ir_post_shred_attempt_heads FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ir_post_shred_attempt_record_select
    ON public.ir_post_shred_attempt_records;
CREATE POLICY ir_post_shred_attempt_record_select
    ON public.ir_post_shred_attempt_records
    FOR SELECT TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_post_shred_attempt_record_insert
    ON public.ir_post_shred_attempt_records;
CREATE POLICY ir_post_shred_attempt_record_insert
    ON public.ir_post_shred_attempt_records
    FOR INSERT TO probectl_provider
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_post_shred_attempt_record_tenant_guard
    ON public.ir_post_shred_attempt_records;
CREATE POLICY ir_post_shred_attempt_record_tenant_guard
    ON public.ir_post_shred_attempt_records
    AS RESTRICTIVE
    FOR ALL TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );

DROP POLICY IF EXISTS ir_post_shred_attempt_head_select
    ON public.ir_post_shred_attempt_heads;
CREATE POLICY ir_post_shred_attempt_head_select
    ON public.ir_post_shred_attempt_heads
    FOR SELECT TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_post_shred_attempt_head_insert
    ON public.ir_post_shred_attempt_heads;
CREATE POLICY ir_post_shred_attempt_head_insert
    ON public.ir_post_shred_attempt_heads
    FOR INSERT TO probectl_provider
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_post_shred_attempt_head_update
    ON public.ir_post_shred_attempt_heads;
CREATE POLICY ir_post_shred_attempt_head_update
    ON public.ir_post_shred_attempt_heads
    FOR UPDATE TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_post_shred_attempt_head_tenant_guard
    ON public.ir_post_shred_attempt_heads;
CREATE POLICY ir_post_shred_attempt_head_tenant_guard
    ON public.ir_post_shred_attempt_heads
    AS RESTRICTIVE
    FOR ALL TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );

REVOKE ALL ON public.ir_post_shred_attempt_records
    FROM PUBLIC, probectl_app, probectl_provider;
GRANT SELECT, INSERT ON public.ir_post_shred_attempt_records
    TO probectl_provider;
REVOKE ALL ON public.ir_post_shred_attempt_heads
    FROM PUBLIC, probectl_app, probectl_provider;
GRANT SELECT, INSERT, UPDATE ON public.ir_post_shred_attempt_heads
    TO probectl_provider;
