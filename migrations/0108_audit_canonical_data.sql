-- 0108_audit_canonical_data.sql — AUD-03: make the audit hash pre-image an
-- unambiguous, lossless encoding.
--
-- The hash chain must cover the EXACT bytes the append side canonicalized. The
-- jsonb `data` column cannot serve that role on read-back: Postgres jsonb
-- reorders object keys (length-then-byte, not Go's lexicographic order), adds
-- separators, and forces a decode→re-marshal that round-trips any integer above
-- 2^53 through float64 and corrupts it. So store the canonical bytes verbatim in
-- a text column and hash THEM; verification reads them back byte-for-byte.
--
-- `data` (jsonb) stays for `->>` queries (fingerprint, subject_hash). A CHECK
-- binds it to data_canonical so the human-readable payload can never silently
-- diverge from what the chain attests. The constraint is ADDed NOT VALID to stay
-- zero-downtime on large existing tables: pre-0108 rows keep data_canonical NULL
-- (and verify via the legacy recompute), while every subsequent write is checked.

ALTER TABLE public.audit_events
    ADD COLUMN IF NOT EXISTS data_canonical text;
ALTER TABLE public.provider_audit_events
    ADD COLUMN IF NOT EXISTS data_canonical text;

COMMENT ON COLUMN public.audit_events.data_canonical IS
    'AUD-03: exact canonical JSON bytes covered by the hash chain; NULL for pre-0108 rows, which verify via the legacy jsonb recompute.';
COMMENT ON COLUMN public.provider_audit_events.data_canonical IS
    'AUD-03: exact canonical JSON bytes covered by the hash chain; NULL for pre-0108 rows, which verify via the legacy jsonb recompute.';

DO $aud03$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'audit_events_data_canonical_matches'
           AND conrelid = 'public.audit_events'::regclass
    ) THEN
        ALTER TABLE public.audit_events
            ADD CONSTRAINT audit_events_data_canonical_matches
            CHECK (data_canonical IS NULL OR data = data_canonical::jsonb)
            NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'provider_audit_events_data_canonical_matches'
           AND conrelid = 'public.provider_audit_events'::regclass
    ) THEN
        ALTER TABLE public.provider_audit_events
            ADD CONSTRAINT provider_audit_events_data_canonical_matches
            CHECK (data_canonical IS NULL OR data = data_canonical::jsonb)
            NOT VALID;
    END IF;
END$aud03$;
