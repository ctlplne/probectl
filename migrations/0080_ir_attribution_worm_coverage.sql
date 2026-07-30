-- 0080_ir_attribution_worm_coverage.sql — IR-6932ab24: bind encrypted
-- attribution to exact signed WORM segments and gate provider retention on a
-- separately durable, signed, continuous coverage watermark.
--
-- The encrypted companion objects remain in the operator's local WORM object
-- store. These two tables contain only hashes, object locators, counts, and
-- signatures: no tenant identifier, operator identity, grant, consent, reason,
-- outcome, or ciphertext is stored in the global provider-control state.

CREATE TABLE IF NOT EXISTS public.ir_attribution_worm_coverage (
    from_seq          bigint PRIMARY KEY CHECK (from_seq > 0),
    to_seq            bigint NOT NULL UNIQUE
                            CHECK (to_seq >= from_seq),
    worm_segment_hash text NOT NULL UNIQUE
                            CHECK (worm_segment_hash ~ '^[0-9a-f]{64}$'),
    companion_key     text NOT NULL UNIQUE
                            CHECK (
                                companion_key ~
                                '^worm/audit/ir/segment-[0-9]{12}-[0-9]{12}[.]ir[.]json$'
                            ),
    companion_hash    text NOT NULL UNIQUE
                            CHECK (companion_hash ~ '^[0-9a-f]{64}$'),
    protected_records bigint NOT NULL
                            CHECK (protected_records BETWEEN 0 AND 1000),
    prev_hash         text NOT NULL
                            CHECK (
                                prev_hash = ''
                                OR prev_hash ~ '^[0-9a-f]{64}$'
                            ),
    hash              text NOT NULL UNIQUE
                            CHECK (hash ~ '^[0-9a-f]{64}$'),
    signature         bytea NOT NULL CHECK (octet_length(signature) = 64),
    created_at        timestamptz NOT NULL DEFAULT now(),
    CHECK (to_seq - from_seq BETWEEN 0 AND 999)
);

CREATE TABLE IF NOT EXISTS public.ir_attribution_worm_coverage_head (
    singleton      boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    covered_seq    bigint NOT NULL DEFAULT 0 CHECK (covered_seq >= 0),
    last_hash      text NOT NULL DEFAULT '',
    companion_hash text NOT NULL DEFAULT '',
    signature      bytea NOT NULL DEFAULT ''::bytea,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (
            covered_seq = 0
            AND last_hash = ''
            AND companion_hash = ''
            AND octet_length(signature) = 0
        )
        OR
        (
            covered_seq > 0
            AND last_hash ~ '^[0-9a-f]{64}$'
            AND companion_hash ~ '^[0-9a-f]{64}$'
            AND octet_length(signature) = 64
        )
    )
);
INSERT INTO public.ir_attribution_worm_coverage_head (singleton)
VALUES (true)
ON CONFLICT (singleton) DO NOTHING;

-- This is provider-control metadata, not tenant data. Keep it outside tenant
-- schemas and expose only the exact append/advance capabilities needed by the
-- provider maintenance role. In particular, coverage rows are immutable.
REVOKE ALL ON public.ir_attribution_worm_coverage
    FROM PUBLIC, probectl_app, probectl_provider;
GRANT SELECT, INSERT ON public.ir_attribution_worm_coverage
    TO probectl_provider;

REVOKE ALL ON public.ir_attribution_worm_coverage_head
    FROM PUBLIC, probectl_app, probectl_provider;
GRANT SELECT, UPDATE ON public.ir_attribution_worm_coverage_head
    TO probectl_provider;
