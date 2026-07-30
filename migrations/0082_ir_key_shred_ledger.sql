-- 0082_ir_key_shred_ledger.sql — IR-132a1231: durable, signed
-- incident-response key-destruction plans and tombstones.
--
-- These rows are provider-control integrity evidence, not tenant payload. They
-- deliberately remain in public for pooled and siloed tenants and deliberately
-- do NOT reference tenants: a completed crypto-shred proof must survive tenant
-- teardown or physical deletion. No key material, key location, actor identity,
-- or plaintext investigation reason is stored here.
--
-- The runtime appends exactly one signed plan and one signed tombstone per
-- tenant. The plan's bounded JSON manifest commits every historical IR key
-- artifact without storing key material or a resolver location. Plans also bind
-- destruction to the exact signed IR attribution/WORM heads observed before
-- deletion. Tombstones bind the completed provider destruction receipt back to
-- that plan. The per-tenant signed head detects removal or reordering.

CREATE TABLE IF NOT EXISTS public.ir_key_shred_records (
    tenant_id            uuid NOT NULL,
    chain_pos            bigint NOT NULL CHECK (chain_pos > 0),
    kind                 text NOT NULL CHECK (kind IN ('plan', 'tombstone')),
    plan_ref             text NOT NULL DEFAULT '',
    covered_seq          bigint NOT NULL CHECK (covered_seq >= 0),
    ir_record_count      bigint NOT NULL CHECK (ir_record_count >= 0),
    ir_last_audit_seq    bigint NOT NULL CHECK (ir_last_audit_seq >= 0),
    ir_last_hash         text NOT NULL,
    artifact_manifest    jsonb NOT NULL,
    actor_hash           text NOT NULL CHECK (actor_hash ~ '^[0-9a-f]{64}$'),
    event_ref            text NOT NULL CHECK (event_ref ~ '^[0-9a-f]{64}$'),
    destroyed_count      bigint NOT NULL DEFAULT 0 CHECK (destroyed_count >= 0),
    destroy_receipt_hash text NOT NULL DEFAULT '',
    prev_hash            text NOT NULL
                               CHECK (
                                   prev_hash = ''
                                   OR prev_hash ~ '^[0-9a-f]{64}$'
                               ),
    hash                 text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    signature            bytea NOT NULL CHECK (octet_length(signature) = 64),
    created_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, chain_pos),
    UNIQUE (tenant_id, kind),
    UNIQUE (tenant_id, event_ref),
    UNIQUE (tenant_id, hash),
    CHECK (jsonb_typeof(artifact_manifest) = 'object'),
    CHECK (
        jsonb_typeof(artifact_manifest -> 'artifacts') = 'array'
        AND jsonb_array_length(artifact_manifest -> 'artifacts')
            BETWEEN 0 AND 1024
    ),
    CHECK (
        octet_length(artifact_manifest::text)
        BETWEEN 2 AND 65536
    ),
    CHECK (covered_seq >= ir_last_audit_seq),
    CHECK (
        (
            ir_record_count = 0
            AND ir_last_audit_seq = 0
            AND ir_last_hash = ''
        )
        OR
        (
            ir_record_count > 0
            AND ir_last_audit_seq > 0
            AND ir_last_hash ~ '^[0-9a-f]{64}$'
        )
    ),
    CHECK (
        (
            kind = 'plan'
            AND chain_pos = 1
            AND plan_ref = ''
            AND destroyed_count = 0
            AND destroy_receipt_hash = ''
        )
        OR
        (
            kind = 'tombstone'
            AND chain_pos = 2
            AND plan_ref ~ '^[0-9a-f]{64}$'
            AND destroyed_count =
                jsonb_array_length(artifact_manifest -> 'artifacts')
            AND destroy_receipt_hash ~ '^[0-9a-f]{64}$'
        )
    )
);

CREATE TABLE IF NOT EXISTS public.ir_key_shred_heads (
    tenant_id      uuid PRIMARY KEY,
    record_count   bigint NOT NULL DEFAULT 0
                          CHECK (record_count BETWEEN 0 AND 2),
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

ALTER TABLE public.ir_key_shred_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ir_key_shred_records FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ir_key_shred_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ir_key_shred_heads FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ir_key_shred_record_select
    ON public.ir_key_shred_records;
CREATE POLICY ir_key_shred_record_select
    ON public.ir_key_shred_records
    FOR SELECT TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_key_shred_record_insert
    ON public.ir_key_shred_records;
CREATE POLICY ir_key_shred_record_insert
    ON public.ir_key_shred_records
    FOR INSERT TO probectl_provider
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_key_shred_record_tenant_guard
    ON public.ir_key_shred_records;
CREATE POLICY ir_key_shred_record_tenant_guard
    ON public.ir_key_shred_records
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

DROP POLICY IF EXISTS ir_key_shred_head_select
    ON public.ir_key_shred_heads;
CREATE POLICY ir_key_shred_head_select
    ON public.ir_key_shred_heads
    FOR SELECT TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_key_shred_head_insert
    ON public.ir_key_shred_heads;
CREATE POLICY ir_key_shred_head_insert
    ON public.ir_key_shred_heads
    FOR INSERT TO probectl_provider
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_key_shred_head_update
    ON public.ir_key_shred_heads;
CREATE POLICY ir_key_shred_head_update
    ON public.ir_key_shred_heads
    FOR UPDATE TO probectl_provider
    USING (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id =
        NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    );
DROP POLICY IF EXISTS ir_key_shred_head_tenant_guard
    ON public.ir_key_shred_heads;
CREATE POLICY ir_key_shred_head_tenant_guard
    ON public.ir_key_shred_heads
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

REVOKE ALL ON public.ir_key_shred_records
    FROM PUBLIC, probectl_app, probectl_provider;
GRANT SELECT, INSERT ON public.ir_key_shred_records TO probectl_provider;
REVOKE ALL ON public.ir_key_shred_heads
    FROM PUBLIC, probectl_app, probectl_provider;
GRANT SELECT, INSERT, UPDATE ON public.ir_key_shred_heads TO probectl_provider;
