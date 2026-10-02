-- 0109_audit_retention_definer_least_priv.sql — AUD-04: the tenant audit
-- trail must not be mutable through a caller-settable GUC.
--
-- Before this migration the least-privilege provider role held SELECT + DELETE
-- on audit_events and UPDATE on audit_stream_heads, and the app role held
-- UPDATE on audit_stream_heads. The RLS policies that "authorized" those
-- mutations keyed on current_setting('probectl.tenant_id') — but ANY role can
-- call set_config('probectl.tenant_id', '<victim>', true) itself, so the GUC is
-- caller-controlled input, not an authority. A compromised provider connection
-- could therefore read ANY tenant's tamper-evident log, DELETE its tail (not
-- just an exported prefix), and rewind audit_stream_heads to hide the gap
-- (TenantVerify walks the shortened chain and still returns nil). A compromised
-- app role could likewise rewind a tenant head. (guardrails G7-1 tenant
-- isolation at the STORAGE layer; G7-7 immutable, tamper-evident audit.)
--
-- The fix moves every privileged audit mutation behind SECURITY DEFINER SQL
-- functions that take the tenant id as an ARGUMENT (never the GUC as authority)
-- and enforce the chain invariants the Go orchestration previously trusted
-- itself to keep:
--   * retention deletes ONLY a contiguous, already-exported prefix
--     (seq <= watermark AND aged), never the tail;
--   * head advancement is monotonic forward-only and preserves the prune
--     anchor, so a head can never be rewound;
--   * the prune anchor advances monotonically and never past the durable head;
--   * full-tenant erasure deletes the whole stream ONLY while the storage-layer
--     erasure fence is engaged (status <> 'deleted' AND audit_write_fenced_at
--     set), re-checked inside the definer.
-- The functions are owned by the migration role and operate on the tenant's
-- actual (pooled public or siloed t_<uuid>) tables, resolved from the registry.
--
-- Direct DELETE/SELECT on audit_events and INSERT/UPDATE on audit_stream_heads
-- are then REVOKEd from the provider role, and UPDATE on audit_stream_heads is
-- REVOKEd from the app role. The app keeps SELECT/INSERT on audit_events
-- (append-only) and SELECT/INSERT on audit_stream_heads (read + first-time
-- head insert via ON CONFLICT DO NOTHING, which needs no UPDATE). Legitimate
-- retention/erase now runs as the least-privilege app role and calls the
-- definers; the provider plane never touches a tenant audit row directly.
--
-- Idempotent (CREATE OR REPLACE, idempotent REVOKE/GRANT) + expand-only
-- (CONTRIBUTING.md): no column/table is dropped or rewritten.

-- Resolve the physical schema that holds one tenant's audit tables. Mirrors
-- internal/tenancy.pgSchemaFor: a siloed tenant lives in t_<uuid-no-dashes>,
-- everything else in public. Fails closed (NULL) for an unknown tenant.
CREATE OR REPLACE FUNCTION public.probectl_tenant_audit_schema(p_tenant uuid)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $probectl_tenant_audit_schema$
    SELECT CASE
               WHEN isolation_model = 'siloed'
               THEN 't_' || replace(id::text, '-', '')
               ELSE 'public'
           END
      FROM public.tenants
     WHERE id = p_tenant
$probectl_tenant_audit_schema$;

REVOKE ALL ON FUNCTION public.probectl_tenant_audit_schema(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_tenant_audit_schema(uuid)
    TO probectl_app, probectl_provider;

-- Monotonic, forward-only tenant head advancement. Replaces the direct
-- INSERT ... ON CONFLICT DO UPDATE the app ran on every audit append. The
-- DO UPDATE fires only when the caller's expected (head_seq, head_hash) still
-- matches AND the new head strictly advances the sequence, so a lower head can
-- never overwrite a higher one. pruned_* is preserved untouched. Returns the
-- number of rows written (the Go caller asserts exactly 1).
CREATE OR REPLACE FUNCTION public.probectl_advance_tenant_audit_head(
    p_tenant uuid,
    p_new_seq bigint,
    p_new_hash text,
    p_pruned_seq bigint,
    p_pruned_hash text,
    p_expect_seq bigint,
    p_expect_hash text
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
        (tenant_id, head_seq, head_hash, pruned_seq, pruned_hash, updated_at)
    VALUES (p_tenant, p_new_seq, p_new_hash, p_pruned_seq, p_pruned_hash, now())
    ON CONFLICT (tenant_id) DO UPDATE
           SET head_seq = EXCLUDED.head_seq,
               head_hash = EXCLUDED.head_hash,
               updated_at = now()
         WHERE heads.head_seq = p_expect_seq
           AND heads.head_hash = p_expect_hash
           AND EXCLUDED.head_seq > heads.head_seq;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END
$probectl_advance_tenant_audit_head$;

REVOKE ALL ON FUNCTION public.probectl_advance_tenant_audit_head(
    uuid, bigint, text, bigint, text, bigint, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_advance_tenant_audit_head(
    uuid, bigint, text, bigint, text, bigint, text
) TO probectl_app, probectl_provider;

-- Monotonic prune-anchor advancement. Replaces the direct UPDATE the retention
-- path ran on audit_stream_heads. The anchor may only move FORWARD (pruned_seq
-- strictly increases) and never past the durable head, and only while the
-- caller's expected head still matches. Returns rows written (caller asserts 1).
CREATE OR REPLACE FUNCTION public.probectl_advance_tenant_audit_prune_anchor(
    p_tenant uuid,
    p_pruned_seq bigint,
    p_pruned_hash text,
    p_expect_head_seq bigint,
    p_expect_head_hash text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $probectl_advance_tenant_audit_prune_anchor$
DECLARE
    v_rows bigint;
BEGIN
    UPDATE public.audit_stream_heads
       SET pruned_seq = p_pruned_seq,
           pruned_hash = p_pruned_hash,
           updated_at = now()
     WHERE tenant_id = p_tenant
       AND head_seq = p_expect_head_seq
       AND head_hash = p_expect_head_hash
       AND pruned_seq < p_pruned_seq
       AND p_pruned_seq <= head_seq;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN v_rows;
END
$probectl_advance_tenant_audit_prune_anchor$;

REVOKE ALL ON FUNCTION public.probectl_advance_tenant_audit_prune_anchor(
    uuid, bigint, text, bigint, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_advance_tenant_audit_prune_anchor(
    uuid, bigint, text, bigint, text
) TO probectl_app, probectl_provider;

-- Prefix-only tenant audit retention delete. Replaces the direct
-- cut-compute + subject-erasure capture + DELETE the provider ran. Deletion is
-- bounded to the CONTIGUOUS prefix of rows that are BOTH already exported
-- (seq <= p_watermark) AND older than p_cutoff; a single ineligible row blocks
-- everything after it, so the retained tail can never be removed. Subject
-- erasures in the doomed prefix are projected into audit_subject_erasures first
-- (append-only evidence) so a malformed marker rolls the whole delete back.
-- Returns (cut_seq, cut_hash, deleted).
CREATE OR REPLACE FUNCTION public.probectl_prune_tenant_audit_prefix(
    p_tenant uuid,
    p_watermark bigint,
    p_cutoff timestamptz,
    p_subject_erase_action text
)
RETURNS TABLE(cut_seq bigint, cut_hash text, deleted bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $probectl_prune_tenant_audit_prefix$
DECLARE
    v_schema text;
    v_events text;
    v_erasures text;
    v_deleted bigint;
BEGIN
    v_schema := public.probectl_tenant_audit_schema(p_tenant);
    IF v_schema IS NULL THEN
        RAISE EXCEPTION 'audit retention: unknown tenant %', p_tenant
            USING ERRCODE = '42501';
    END IF;
    v_events := format('%I.audit_events', v_schema);
    v_erasures := format('%I.audit_subject_erasures', v_schema);

    -- End of the contiguous eligible (exported AND aged) prefix.
    EXECUTE format(
        $cut$
        WITH ordered AS (
            SELECT seq,
                   hash,
                   (seq <= $1 AND created_at < $2) AS eligible,
                   bool_or(NOT (seq <= $1 AND created_at < $2))
                     OVER (ORDER BY seq
                           ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)
                     AS blocked
              FROM %s
             WHERE tenant_id = $3
        )
        SELECT seq, hash
          FROM ordered
         WHERE eligible AND NOT blocked
         ORDER BY seq DESC
         LIMIT 1
        $cut$,
        v_events
    )
    INTO cut_seq, cut_hash
    USING p_watermark, p_cutoff, p_tenant;

    IF cut_seq IS NULL THEN
        cut_seq := 0;
        cut_hash := '';
        deleted := 0;
        RETURN NEXT;
        RETURN;
    END IF;

    -- Project any subject-erasure markers in the doomed prefix BEFORE deleting.
    EXECUTE format(
        $capture$
        INSERT INTO %s (tenant_id, subject_hash, created_at)
        SELECT tenant_id, data->>'subject_hash', min(created_at)
          FROM %s
         WHERE tenant_id = $1
           AND seq <= $2
           AND action = $3
         GROUP BY tenant_id, data->>'subject_hash'
        ON CONFLICT (tenant_id, subject_hash) DO NOTHING
        $capture$,
        v_erasures,
        v_events
    )
    USING p_tenant, cut_seq, p_subject_erase_action;

    -- Prefix-only: never deletes beyond the contiguous eligible cut.
    EXECUTE format(
        'DELETE FROM %s WHERE tenant_id = $1 AND seq <= $2',
        v_events
    )
    USING p_tenant, cut_seq;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    IF v_deleted = 0 THEN
        RAISE EXCEPTION 'audit retention: eligible prefix disappeared for tenant %',
            p_tenant
            USING ERRCODE = '40001';
    END IF;
    deleted := v_deleted;
    RETURN NEXT;
END
$probectl_prune_tenant_audit_prefix$;

REVOKE ALL ON FUNCTION public.probectl_prune_tenant_audit_prefix(
    uuid, bigint, timestamptz, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_prune_tenant_audit_prefix(
    uuid, bigint, timestamptz, text
) TO probectl_app, probectl_provider;

-- Full-tenant audit erasure. Replaces the direct whole-stream DELETE the
-- provider ran during verified offboarding. The erasure fence is re-checked
-- INSIDE the definer (status <> 'deleted' AND audit_write_fenced_at set) under
-- the canonical audit stream lock, so this can never run for a live tenant even
-- if a caller sets the GUC. Deletes both append-only tables, asserts zero
-- remain, and returns the total rows removed.
CREATE OR REPLACE FUNCTION public.probectl_erase_tenant_audit(p_tenant uuid)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $probectl_erase_tenant_audit$
DECLARE
    v_schema text;
    v_events text;
    v_erasures text;
    v_status text;
    v_fenced boolean;
    v_deleted bigint;
    v_total bigint := 0;
    v_remaining bigint;
BEGIN
    v_schema := public.probectl_tenant_audit_schema(p_tenant);
    IF v_schema IS NULL THEN
        RAISE EXCEPTION 'audit erasure: unknown tenant %', p_tenant
            USING ERRCODE = '42501';
    END IF;
    v_events := format('%I.audit_events', v_schema);
    v_erasures := format('%I.audit_subject_erasures', v_schema);

    PERFORM pg_advisory_xact_lock(
        hashtextextended('audit:' || p_tenant::text, 0)
    );
    SELECT status, audit_write_fenced_at IS NOT NULL
      INTO v_status, v_fenced
      FROM public.tenants
     WHERE id = p_tenant
     FOR KEY SHARE;
    IF NOT FOUND OR NOT v_fenced OR v_status = 'deleted' THEN
        RAISE EXCEPTION
            'audit erasure fence invalid for tenant %: status=%, fenced=%',
            p_tenant, v_status, v_fenced
            USING ERRCODE = '55000';
    END IF;

    EXECUTE format('DELETE FROM %s WHERE tenant_id = $1', v_events)
        USING p_tenant;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    v_total := v_total + v_deleted;

    EXECUTE format('DELETE FROM %s WHERE tenant_id = $1', v_erasures)
        USING p_tenant;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    v_total := v_total + v_deleted;

    EXECUTE format('SELECT count(*) FROM %s WHERE tenant_id = $1', v_events)
        INTO v_remaining USING p_tenant;
    IF v_remaining <> 0 THEN
        RAISE EXCEPTION 'audit erasure: % audit_events rows remain for tenant %',
            v_remaining, p_tenant;
    END IF;
    EXECUTE format('SELECT count(*) FROM %s WHERE tenant_id = $1', v_erasures)
        INTO v_remaining USING p_tenant;
    IF v_remaining <> 0 THEN
        RAISE EXCEPTION
            'audit erasure: % audit_subject_erasures rows remain for tenant %',
            v_remaining, p_tenant;
    END IF;

    RETURN v_total;
END
$probectl_erase_tenant_audit$;

REVOKE ALL ON FUNCTION public.probectl_erase_tenant_audit(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_erase_tenant_audit(uuid)
    TO probectl_app, probectl_provider;

-- Count the tenant's remaining append-only audit rows (both tables), for the
-- pre-tombstone verification the provider plane runs without direct SELECT.
CREATE OR REPLACE FUNCTION public.probectl_count_tenant_audit_rows(p_tenant uuid)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $probectl_count_tenant_audit_rows$
DECLARE
    v_schema text;
    v_events bigint;
    v_erasures bigint;
BEGIN
    v_schema := public.probectl_tenant_audit_schema(p_tenant);
    IF v_schema IS NULL THEN
        RAISE EXCEPTION 'audit count: unknown tenant %', p_tenant
            USING ERRCODE = '42501';
    END IF;
    EXECUTE format(
        'SELECT count(*) FROM %I.audit_events WHERE tenant_id = $1', v_schema
    ) INTO v_events USING p_tenant;
    EXECUTE format(
        'SELECT count(*) FROM %I.audit_subject_erasures WHERE tenant_id = $1',
        v_schema
    ) INTO v_erasures USING p_tenant;
    RETURN v_events + v_erasures;
END
$probectl_count_tenant_audit_rows$;

REVOKE ALL ON FUNCTION public.probectl_count_tenant_audit_rows(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_count_tenant_audit_rows(uuid)
    TO probectl_app, probectl_provider;

-- Now remove the caller-settable-GUC authority. The provider role keeps no
-- direct read/mutate path to a tenant audit row; the app role keeps the
-- append-only (SELECT, INSERT) shape and loses head UPDATE. Idempotent.
REVOKE SELECT, DELETE ON public.audit_events FROM probectl_provider;
REVOKE INSERT, UPDATE ON public.audit_stream_heads FROM probectl_provider;
REVOKE UPDATE ON public.audit_stream_heads FROM probectl_app;

-- Converge every already-provisioned PostgreSQL silo: the provider's direct
-- SELECT/DELETE on the routed audit_events is withdrawn too (the definers above
-- resolve and operate on the silo schema). Future silos get the hardened recipe
-- from ee/silo's provision plan. audit_stream_heads is deployment-global
-- (public) even for silos, so its grants are handled once above.
DO $silo_audit_least_priv$
DECLARE
    silo record;
BEGIN
    FOR silo IN
        SELECT 't_' || replace(id::text, '-', '') AS schema_name
          FROM public.tenants
         WHERE isolation_model = 'siloed'
    LOOP
        IF to_regclass(format('%I.audit_events', silo.schema_name)) IS NULL THEN
            CONTINUE;
        END IF;
        EXECUTE format(
            'REVOKE SELECT, DELETE ON %I.audit_events FROM probectl_provider',
            silo.schema_name
        );
    END LOOP;
END
$silo_audit_least_priv$;
