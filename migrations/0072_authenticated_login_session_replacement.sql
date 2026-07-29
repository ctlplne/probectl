-- 0072_authenticated_login_session_replacement.sql
-- A successful IdP callback is a new authentication event, not a permission
-- refresh. Keep ordinary session rotation source-authoritative, but give login
-- replacement a separate atomic path that:
--   1. consumes a current or pre-HMAC predecessor regardless of old identity;
--   2. adopts the freshly verified tenant/user/MFA/preferences and fresh TTL;
--   3. remembers a consumed predecessor so a concurrent callback cannot mint a
--      second successor after observing the first callback's update.

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS replaced_at timestamptz;

-- A retained predecessor is an inactive tombstone. Resolution and ordinary
-- permission refresh both fail closed on it.
CREATE OR REPLACE FUNCTION pretenant_lookup_session(
    p_token_hash bytea,
    p_idle_timeout interval
)
RETURNS TABLE(
    id uuid,
    tenant_id uuid,
    user_id uuid,
    email text,
    display_name text,
    mfa_satisfied boolean,
    time_zone text,
    locale text,
    tenant_time_zone text,
    tenant_locale text,
    expires_at timestamptz,
    created_at timestamptz,
    last_activity_at timestamptz,
    authorization_hash bytea
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE public.sessions AS s
       SET last_activity_at = now()
     WHERE s.token_hash = p_token_hash
       AND s.replaced_at IS NULL
       AND s.expires_at > now()
       AND s.last_activity_at > now() - p_idle_timeout
     RETURNING
       s.id, s.tenant_id, s.user_id, s.email, s.display_name, s.mfa_satisfied,
       s.time_zone, s.locale, s.tenant_time_zone, s.tenant_locale,
       s.expires_at, s.created_at, s.last_activity_at, s.authorization_hash
$$;

CREATE OR REPLACE FUNCTION pretenant_rotate_session(
    p_old_hash bytea,
    p_new_hash bytea,
    p_tenant_id uuid,
    p_user_id uuid,
    p_authorization_hash bytea
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH rotated AS (
        UPDATE public.sessions AS s
           SET token_hash = p_new_hash,
               last_activity_at = now(),
               authorization_hash = COALESCE(p_authorization_hash, '\x'::bytea)
         WHERE s.token_hash = p_old_hash
           AND s.replaced_at IS NULL
           AND s.tenant_id = p_tenant_id
           AND s.user_id = p_user_id
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM rotated)
$$;

-- Logging out an obsolete browser tab must not erase the concurrency marker:
-- delete only live sessions. The active successor still logs out normally.
CREATE OR REPLACE FUNCTION pretenant_delete_session(p_token_hash bytea)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH deleted AS (
        DELETE FROM public.sessions AS s
         WHERE s.token_hash = p_token_hash
           AND s.replaced_at IS NULL
         RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM deleted)
$$;

-- Temporarily restore schema CREATE so the non-login boundary role can receive
-- ownership of this one reviewed function. It is revoked again below.
GRANT CREATE ON SCHEMA public TO probectl_pretenant_auth;
GRANT INSERT ON sessions TO probectl_pretenant_auth;

CREATE OR REPLACE FUNCTION pretenant_replace_authenticated_session(
    p_old_hash bytea,
    p_legacy_old_hash bytea,
    p_new_hash bytea,
    p_tenant_id uuid,
    p_user_id uuid,
    p_email text,
    p_display_name text,
    p_mfa_satisfied boolean,
    p_time_zone text,
    p_locale text,
    p_tenant_time_zone text,
    p_tenant_locale text,
    p_expires_at timestamptz,
    p_created_at timestamptz,
    p_last_activity_at timestamptz,
    p_authorization_hash bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    predecessor record;
    found_predecessor boolean := false;
    already_consumed boolean := false;
BEGIN
    -- Lock every keyed/legacy candidate in a deterministic order. A concurrent
    -- callback waits here, then observes replaced_at and returns false.
    FOR predecessor IN
        SELECT s.id, s.replaced_at
          FROM public.sessions AS s
         WHERE s.token_hash = p_old_hash
            OR (p_legacy_old_hash IS NOT NULL AND s.token_hash = p_legacy_old_hash)
         ORDER BY s.token_hash
         FOR UPDATE
    LOOP
        found_predecessor := true;
        already_consumed := already_consumed OR (predecessor.replaced_at IS NOT NULL);
    END LOOP;

    IF found_predecessor THEN
        UPDATE public.sessions AS s
           SET replaced_at = COALESCE(s.replaced_at, now())
         WHERE s.token_hash = p_old_hash
            OR (p_legacy_old_hash IS NOT NULL AND s.token_hash = p_legacy_old_hash);
    END IF;

    IF already_consumed THEN
        RETURN false;
    END IF;

    INSERT INTO public.sessions (
        token_hash, tenant_id, user_id, email, display_name, mfa_satisfied,
        time_zone, locale, tenant_time_zone, tenant_locale, expires_at,
        created_at, last_activity_at, authorization_hash
    )
    VALUES (
        p_new_hash, p_tenant_id, p_user_id, p_email, p_display_name, p_mfa_satisfied,
        COALESCE(NULLIF(p_time_zone, ''), 'UTC'),
        COALESCE(NULLIF(p_locale, ''), 'en'),
        COALESCE(NULLIF(p_tenant_time_zone, ''), 'UTC'),
        COALESCE(NULLIF(p_tenant_locale, ''), 'en'),
        p_expires_at, p_created_at, p_last_activity_at,
        COALESCE(p_authorization_hash, '\x'::bytea)
    );
    RETURN true;
END
$$;

ALTER FUNCTION pretenant_replace_authenticated_session(
    bytea, bytea, bytea, uuid, uuid, text, text, boolean,
    text, text, text, text, timestamptz, timestamptz, timestamptz, bytea
) OWNER TO probectl_pretenant_auth;
REVOKE ALL ON FUNCTION pretenant_replace_authenticated_session(
    bytea, bytea, bytea, uuid, uuid, text, text, boolean,
    text, text, text, text, timestamptz, timestamptz, timestamptz, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pretenant_replace_authenticated_session(
    bytea, bytea, bytea, uuid, uuid, text, text, boolean,
    text, text, text, text, timestamptz, timestamptz, timestamptz, bytea
) TO probectl_app;

REVOKE CREATE ON SCHEMA public FROM probectl_pretenant_auth;
