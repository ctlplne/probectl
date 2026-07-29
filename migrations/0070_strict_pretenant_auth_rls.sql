-- 0070_strict_pretenant_auth_rls.sql
-- Tenant isolation is the outermost boundary: an application-role statement
-- with no probectl.tenant_id must see and change zero rows. Authentication still
-- has to resolve an opaque token hash before its tenant is known, so expose only
-- purpose-built SECURITY DEFINER functions owned by a non-login role. This is
-- the same storage-boundary pattern introduced for OTLP by migration 0048.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'probectl_pretenant_auth') THEN
        CREATE ROLE probectl_pretenant_auth NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END $$;

-- PostgreSQL requires a function's new owner to hold CREATE on its schema.
-- Grant it only while ownership is transferred inside this migration; revoke
-- it before commit so the runtime boundary role cannot create arbitrary SQL.
GRANT USAGE, CREATE ON SCHEMA public TO probectl_pretenant_auth;
REVOKE ALL ON sessions, mcp_tokens, scim_tokens, agent_enroll_tokens, agent_identities
FROM probectl_pretenant_auth;
GRANT SELECT, UPDATE, DELETE ON sessions TO probectl_pretenant_auth;
GRANT SELECT, UPDATE ON mcp_tokens, scim_tokens, agent_enroll_tokens
TO probectl_pretenant_auth;
GRANT SELECT ON agent_identities TO probectl_pretenant_auth;

-- Session resolution is deliberately hash-only. Absolute and idle expiry are
-- checked in the same statement that records activity.
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
       AND s.expires_at > now()
       AND s.last_activity_at > now() - p_idle_timeout
     RETURNING
       s.id, s.tenant_id, s.user_id, s.email, s.display_name, s.mfa_satisfied,
       s.time_zone, s.locale, s.tenant_time_zone, s.tenant_locale,
       s.expires_at, s.created_at, s.last_activity_at, s.authorization_hash
$$;
ALTER FUNCTION pretenant_lookup_session(bytea, interval) OWNER TO probectl_pretenant_auth;
REVOKE ALL ON FUNCTION pretenant_lookup_session(bytea, interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pretenant_lookup_session(bytea, interval) TO probectl_app;

-- Rotation is an in-place key replacement: every identity, MFA, preference,
-- and absolute-lifetime field therefore remains database-authoritative. The
-- caller may change only the opaque token hash and authorization fingerprint;
-- activity is stamped by the database. A mismatched tenant/user gets false.
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
           AND s.tenant_id = p_tenant_id
           AND s.user_id = p_user_id
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM rotated)
$$;
ALTER FUNCTION pretenant_rotate_session(
    bytea, bytea, uuid, uuid, bytea
) OWNER TO probectl_pretenant_auth;
REVOKE ALL ON FUNCTION pretenant_rotate_session(
    bytea, bytea, uuid, uuid, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pretenant_rotate_session(
    bytea, bytea, uuid, uuid, bytea
) TO probectl_app;

CREATE OR REPLACE FUNCTION pretenant_delete_session(p_token_hash bytea)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH deleted AS (
        DELETE FROM public.sessions AS s
         WHERE s.token_hash = p_token_hash
         RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM deleted)
$$;
ALTER FUNCTION pretenant_delete_session(bytea) OWNER TO probectl_pretenant_auth;
REVOKE ALL ON FUNCTION pretenant_delete_session(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pretenant_delete_session(bytea) TO probectl_app;

CREATE OR REPLACE FUNCTION pretenant_authenticate_mcp_token(p_token_hash bytea)
RETURNS TABLE(tenant_id uuid, user_id uuid)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE public.mcp_tokens AS t
       SET last_used_at = now()
     WHERE t.token_hash = p_token_hash
       AND t.revoked_at IS NULL
     RETURNING t.tenant_id, t.user_id
$$;
ALTER FUNCTION pretenant_authenticate_mcp_token(bytea) OWNER TO probectl_pretenant_auth;
REVOKE ALL ON FUNCTION pretenant_authenticate_mcp_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pretenant_authenticate_mcp_token(bytea) TO probectl_app;

CREATE OR REPLACE FUNCTION pretenant_authenticate_scim_token(p_token_hash bytea)
RETURNS TABLE(tenant_id uuid)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE public.scim_tokens AS t
       SET last_used_at = now()
     WHERE t.token_hash = p_token_hash
       AND t.revoked_at IS NULL
     RETURNING t.tenant_id
$$;
ALTER FUNCTION pretenant_authenticate_scim_token(bytea) OWNER TO probectl_pretenant_auth;
REVOKE ALL ON FUNCTION pretenant_authenticate_scim_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pretenant_authenticate_scim_token(bytea) TO probectl_app;

CREATE OR REPLACE FUNCTION pretenant_consume_agent_enroll_token(
    p_token_hash bytea,
    p_used_by_agent text
)
RETURNS TABLE(tenant_id uuid, agent_id text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    UPDATE public.agent_enroll_tokens AS t
       SET used_at = now(), used_by_agent = p_used_by_agent
     WHERE t.token_hash = p_token_hash
       AND t.used_at IS NULL
       AND t.revoked_at IS NULL
       AND t.expires_at > now()
     RETURNING t.tenant_id, COALESCE(t.agent_id, '')
$$;
ALTER FUNCTION pretenant_consume_agent_enroll_token(bytea, text) OWNER TO probectl_pretenant_auth;
REVOKE ALL ON FUNCTION pretenant_consume_agent_enroll_token(bytea, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pretenant_consume_agent_enroll_token(bytea, text) TO probectl_app;

-- Enrollment-token cancellation and the deployment-wide certificate deny-list
-- are provider operations, not pre-tenant authentication. Keep them callable
-- only after the runtime has entered the distinct probectl_provider domain.
CREATE OR REPLACE FUNCTION provider_revoke_agent_enroll_token(p_id uuid)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH revoked AS (
        UPDATE public.agent_enroll_tokens AS t
           SET revoked_at = now()
         WHERE t.id = p_id
           AND t.used_at IS NULL
           AND t.revoked_at IS NULL
         RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM revoked)
$$;
ALTER FUNCTION provider_revoke_agent_enroll_token(uuid) OWNER TO probectl_pretenant_auth;
REVOKE ALL ON FUNCTION provider_revoke_agent_enroll_token(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION provider_revoke_agent_enroll_token(uuid) TO probectl_provider;

CREATE OR REPLACE FUNCTION provider_list_revoked_agent_identities()
RETURNS TABLE(serial text, spiffe_id text, live boolean)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT i.serial, i.spiffe_id, i.not_after > now()
      FROM public.agent_identities AS i
     WHERE i.revoked_at IS NOT NULL
$$;
ALTER FUNCTION provider_list_revoked_agent_identities() OWNER TO probectl_pretenant_auth;
REVOKE ALL ON FUNCTION provider_list_revoked_agent_identities() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION provider_list_revoked_agent_identities() TO probectl_provider;

REVOKE CREATE ON SCHEMA public FROM probectl_pretenant_auth;

-- Direct application-role access always requires a tenant GUC. The dedicated
-- pre-tenant role is admitted by a separate role-specific policy and can be
-- reached only through the EXECUTE grants above.
DROP POLICY IF EXISTS tenant_isolation ON sessions;
CREATE POLICY tenant_isolation ON sessions
  FOR ALL TO probectl_app
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS pretenant_auth_access ON sessions;
CREATE POLICY pretenant_auth_access ON sessions
  FOR ALL TO probectl_pretenant_auth USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS tenant_isolation ON mcp_tokens;
CREATE POLICY tenant_isolation ON mcp_tokens
  FOR ALL TO probectl_app
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS pretenant_auth_access ON mcp_tokens;
CREATE POLICY pretenant_auth_access ON mcp_tokens
  FOR ALL TO probectl_pretenant_auth USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS tenant_isolation ON scim_tokens;
CREATE POLICY tenant_isolation ON scim_tokens
  FOR ALL TO probectl_app
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS pretenant_auth_access ON scim_tokens;
CREATE POLICY pretenant_auth_access ON scim_tokens
  FOR ALL TO probectl_pretenant_auth USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS tenant_isolation ON agent_enroll_tokens;
CREATE POLICY tenant_isolation ON agent_enroll_tokens
  FOR ALL TO probectl_app
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS pretenant_auth_access ON agent_enroll_tokens;
CREATE POLICY pretenant_auth_access ON agent_enroll_tokens
  FOR ALL TO probectl_pretenant_auth USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS tenant_isolation ON agent_identities;
CREATE POLICY tenant_isolation ON agent_identities
  FOR ALL TO probectl_app
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS pretenant_auth_access ON agent_identities;
CREATE POLICY pretenant_auth_access ON agent_identities
  FOR ALL TO probectl_pretenant_auth USING (true) WITH CHECK (true);

-- Break-glass is provider operational metadata, not a pre-tenant auth table.
-- Tenant-app access, if ever granted, remains tenant-scoped; provider access is
-- explicit and role-specific rather than smuggled through an unset GUC.
DROP POLICY IF EXISTS tenant_isolation ON break_glass_grants;
CREATE POLICY tenant_isolation ON break_glass_grants
  FOR ALL TO probectl_app
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS provider_break_glass_access ON break_glass_grants;
CREATE POLICY provider_break_glass_access ON break_glass_grants
  FOR ALL TO probectl_provider USING (true) WITH CHECK (true);
