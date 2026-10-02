-- 0110_audit_stream_head_signature.sql — AUD-01: anchor the tenant audit chain
-- OUTSIDE the database's trust domain with an Ed25519 signature over the durable
-- head.
--
-- The per-tenant hash chain and its durable head (audit_stream_heads) both live
-- in Postgres, so a writer with direct table access — the compose stack's login
-- user, a DB superuser — can rewrite a row, recompute computeHash across the
-- suffix, and UPDATE audit_stream_heads to match. TenantVerify's hash-chain walk
-- then follows that internally consistent forgery and still returns nil, because
-- nothing outside the database vouches for the chain. (docs/guardrails.md G7-7
-- immutable, tamper-evident audit.)
--
-- The fix signs the durable head with the control plane's EXISTING offline
-- Ed25519 WORM key (the same key that signs the provider WORM export; no new key,
-- no external notary, no phone-home). The signature is computed in Go, over
-- (tenant_id, head_seq, head_hash), and ONLY the resulting bytes are stored here:
-- the signing key never reaches the database or a SQL function (G7-7). A DB
-- writer who rewrites rows, recomputes the chain, and updates the head cannot
-- forge the signature over the new head, so TenantVerify's new signature check
-- fails and names the head position.
--
-- Expand-only + idempotent (CONTRIBUTING.md): a NULLable column is added
-- (ADD COLUMN IF NOT EXISTS), and the AUD-04 head-advance definer gains a
-- trailing DEFAULTed argument so a rolling-upgrade N-1 binary (which calls it
-- with seven positional arguments) still resolves to the one function, leaving
-- the signature NULL — which verification treats as an un-anchored head and
-- fails closed, never as a silent pass.

-- The signature bytes over the durable head. NULL for a legacy head written
-- before this column, or when head anchoring is not configured; verification
-- falls back to the pre-AUD-01 hash-only check only when no anchor key is
-- configured in the control plane (see internal/audit/headanchor.go).
ALTER TABLE audit_stream_heads
    ADD COLUMN IF NOT EXISTS head_sig bytea;

-- Re-declare the AUD-04 monotonic, forward-only head-advance definer with a
-- trailing p_head_sig argument and store it on both the first-time INSERT and
-- the forward DO UPDATE. Everything else is unchanged from 0109: the DO UPDATE
-- still fires only when the caller's expected (head_seq, head_hash) still matches
-- AND the new head strictly advances the sequence, so a lower head can never
-- overwrite a higher one, pruned_* is preserved untouched, and the key is never
-- seen by the database. p_head_sig DEFAULTs to NULL so a seven-argument call
-- from an N-1 binary during a rolling upgrade still resolves to this function.
CREATE OR REPLACE FUNCTION public.probectl_advance_tenant_audit_head(
    p_tenant uuid,
    p_new_seq bigint,
    p_new_hash text,
    p_pruned_seq bigint,
    p_pruned_hash text,
    p_expect_seq bigint,
    p_expect_hash text,
    p_head_sig bytea DEFAULT NULL
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $probectl_advance_tenant_audit_head$
DECLARE
    v_rows bigint;
BEGIN
    INSERT INTO public.audit_stream_heads AS heads
        (tenant_id, head_seq, head_hash, pruned_seq, pruned_hash, head_sig, updated_at)
    VALUES (p_tenant, p_new_seq, p_new_hash, p_pruned_seq, p_pruned_hash, p_head_sig, now())
    ON CONFLICT (tenant_id) DO UPDATE
           SET head_seq = EXCLUDED.head_seq,
               head_hash = EXCLUDED.head_hash,
               head_sig = EXCLUDED.head_sig,
               updated_at = now()
         WHERE heads.head_seq = p_expect_seq
           AND heads.head_hash = p_expect_hash
           AND EXCLUDED.head_seq > heads.head_seq;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END
$probectl_advance_tenant_audit_head$;

-- Retire the seven-argument variant now that the eight-argument function (whose
-- last argument DEFAULTs) serves seven-positional callers too. No database
-- object depends on it (it is invoked only from internal/audit). Idempotent.
DROP FUNCTION IF EXISTS public.probectl_advance_tenant_audit_head(
    uuid, bigint, text, bigint, text, bigint, text
);

REVOKE ALL ON FUNCTION public.probectl_advance_tenant_audit_head(
    uuid, bigint, text, bigint, text, bigint, text, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_advance_tenant_audit_head(
    uuid, bigint, text, bigint, text, bigint, text, bytea
) TO probectl_app, probectl_provider;
