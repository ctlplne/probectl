-- 0073_silo_pretenant_credential_locators.sql
-- A pre-tenant bearer hash must identify its tenant before the application can
-- route into that tenant's physical Postgres schema. Keep only opaque locator
-- and revocation metadata in public; detailed session/credential rows remain in
-- the tenant-owned table (public for pooled tenants, t_<uuid> for silos).

CREATE TABLE IF NOT EXISTS credential_locators (
    credential_kind text        NOT NULL
        CHECK (credential_kind IN ('session', 'mcp', 'scim', 'otlp', 'agent_enroll')),
    credential_id   uuid        NOT NULL,
    token_hash      bytea       NOT NULL,
    tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    consumed_at     timestamptz,
    replaced_at     timestamptz,
    PRIMARY KEY (credential_kind, token_hash),
    UNIQUE (credential_kind, credential_id)
);
-- CREATE TABLE IF NOT EXISTS does not upgrade a table left by an interrupted
-- operator rehearsal or an older pre-release build. Keep every field additive
-- so this migration is genuinely rerunnable against that state.
ALTER TABLE credential_locators
    ADD COLUMN IF NOT EXISTS credential_kind text;
ALTER TABLE credential_locators
    ADD COLUMN IF NOT EXISTS credential_id uuid;
ALTER TABLE credential_locators
    ADD COLUMN IF NOT EXISTS token_hash bytea;
ALTER TABLE credential_locators
    ADD COLUMN IF NOT EXISTS tenant_id uuid;
ALTER TABLE credential_locators
    ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE credential_locators
    ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
ALTER TABLE credential_locators
    ADD COLUMN IF NOT EXISTS consumed_at timestamptz;
ALTER TABLE credential_locators
    ADD COLUMN IF NOT EXISTS replaced_at timestamptz;
CREATE INDEX IF NOT EXISTS credential_locators_tenant_idx
    ON credential_locators (tenant_id, credential_kind);

-- Certificate verification needs a deployment-wide deny-list before a tenant
-- transaction exists. This table is revocation metadata only; issuance detail
-- (including the full identity history) remains tenant-owned.
CREATE TABLE IF NOT EXISTS agent_identity_revocations (
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id   text        NOT NULL,
    spiffe_id  text        NOT NULL,
    serial     text        NOT NULL,
    not_after  timestamptz NOT NULL,
    revoked_at timestamptz NOT NULL,
    revoked_by text        NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, serial),
    UNIQUE (serial)
);
ALTER TABLE agent_identity_revocations
    ADD COLUMN IF NOT EXISTS tenant_id uuid;
ALTER TABLE agent_identity_revocations
    ADD COLUMN IF NOT EXISTS agent_id text;
ALTER TABLE agent_identity_revocations
    ADD COLUMN IF NOT EXISTS spiffe_id text;
ALTER TABLE agent_identity_revocations
    ADD COLUMN IF NOT EXISTS serial text;
ALTER TABLE agent_identity_revocations
    ADD COLUMN IF NOT EXISTS not_after timestamptz;
ALTER TABLE agent_identity_revocations
    ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
ALTER TABLE agent_identity_revocations
    ADD COLUMN IF NOT EXISTS revoked_by text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS agent_identity_revocations_spiffe_idx
    ON agent_identity_revocations (spiffe_id);

ALTER TABLE credential_locators ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_locators FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON credential_locators;
CREATE POLICY tenant_isolation ON credential_locators
  FOR ALL TO probectl_app
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS pretenant_auth_access ON credential_locators;
CREATE POLICY pretenant_auth_access ON credential_locators
  FOR ALL TO probectl_pretenant_auth USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS provider_locator_erasure ON credential_locators;
CREATE POLICY provider_locator_erasure ON credential_locators
  FOR ALL TO probectl_provider USING (true) WITH CHECK (true);

ALTER TABLE agent_identity_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_identity_revocations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON agent_identity_revocations;
CREATE POLICY tenant_isolation ON agent_identity_revocations
  FOR ALL TO probectl_app
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS pretenant_auth_access ON agent_identity_revocations;
CREATE POLICY pretenant_auth_access ON agent_identity_revocations
  FOR ALL TO probectl_pretenant_auth USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS provider_revocation_erasure ON agent_identity_revocations;
CREATE POLICY provider_revocation_erasure ON agent_identity_revocations
  FOR ALL TO probectl_provider USING (true) WITH CHECK (true);

GRANT SELECT, DELETE
ON credential_locators, agent_identity_revocations
TO probectl_provider;

GRANT USAGE, CREATE ON SCHEMA public TO probectl_pretenant_auth;
REVOKE ALL ON credential_locators, agent_identity_revocations
FROM probectl_pretenant_auth;
GRANT SELECT, INSERT, UPDATE, DELETE
ON credential_locators, agent_identity_revocations
TO probectl_pretenant_auth;

-- Register a freshly-created tenant-owned row. The tenant GUC is checked inside
-- the definer boundary, so an application transaction cannot register a hash
-- for another tenant.
CREATE OR REPLACE FUNCTION pretenant_register_credential(
    p_kind text,
    p_credential_id uuid,
    p_token_hash bytea,
    p_tenant_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_tenant_id IS DISTINCT FROM
       NULLIF(current_setting('probectl.tenant_id', true), '')::uuid THEN
        RETURN false;
    END IF;
    INSERT INTO public.credential_locators (
        credential_kind, credential_id, token_hash, tenant_id
    ) VALUES (p_kind, p_credential_id, p_token_hash, p_tenant_id);
    RETURN true;
END
$$;

-- Catch-up/restores can replay existing silo rows. An existing locator may be
-- updated only when both its tenant and detailed-row id already agree.
CREATE OR REPLACE FUNCTION pretenant_sync_credential(
    p_kind text,
    p_credential_id uuid,
    p_token_hash bytea,
    p_tenant_id uuid,
    p_revoked_at timestamptz,
    p_consumed_at timestamptz,
    p_replaced_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    changed integer;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
       NULLIF(current_setting('probectl.tenant_id', true), '')::uuid THEN
        RETURN false;
    END IF;

    UPDATE public.credential_locators AS l
       SET token_hash = p_token_hash,
           revoked_at = p_revoked_at,
           consumed_at = p_consumed_at,
           replaced_at = p_replaced_at
     WHERE l.credential_kind = p_kind
       AND l.credential_id = p_credential_id
       AND l.tenant_id = p_tenant_id;
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed = 1 THEN
        RETURN true;
    END IF;

    INSERT INTO public.credential_locators (
        credential_kind, credential_id, token_hash, tenant_id,
        revoked_at, consumed_at, replaced_at
    ) VALUES (
        p_kind, p_credential_id, p_token_hash, p_tenant_id,
        p_revoked_at, p_consumed_at, p_replaced_at
    );
    RETURN true;
END
$$;

CREATE OR REPLACE FUNCTION pretenant_resolve_credential(
    p_kind text,
    p_token_hash bytea
)
RETURNS TABLE(tenant_id uuid)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT l.tenant_id
      FROM public.credential_locators AS l
     WHERE l.credential_kind = p_kind
       AND l.token_hash = p_token_hash
       AND l.revoked_at IS NULL
       AND l.consumed_at IS NULL
       AND l.replaced_at IS NULL
$$;

CREATE OR REPLACE FUNCTION pretenant_resolve_credential_id(
    p_kind text,
    p_credential_id uuid
)
RETURNS TABLE(tenant_id uuid)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT l.tenant_id
      FROM public.credential_locators AS l
     WHERE l.credential_kind = p_kind
       AND l.credential_id = p_credential_id
       AND l.revoked_at IS NULL
       AND l.consumed_at IS NULL
       AND l.replaced_at IS NULL
$$;

CREATE OR REPLACE FUNCTION pretenant_revoke_credential(
    p_kind text,
    p_token_hash bytea,
    p_tenant_id uuid
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH revoked AS (
        UPDATE public.credential_locators AS l
           SET revoked_at = COALESCE(l.revoked_at, now())
         WHERE l.credential_kind = p_kind
           AND l.token_hash = p_token_hash
           AND l.tenant_id = p_tenant_id
           AND p_tenant_id IS NOT DISTINCT FROM
               NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
         RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM revoked)
$$;

-- Subject erasure captures tenant-owned session/MCP row ids before deleting
-- those detail rows. Remove the corresponding global hash locators inside the
-- same tenant transaction; a foreign-tenant id is silently out of scope.
CREATE OR REPLACE FUNCTION pretenant_delete_credential_locators(
    p_kind text,
    p_credential_ids uuid[],
    p_tenant_id uuid
)
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH deleted AS (
        DELETE FROM public.credential_locators AS l
         WHERE l.credential_kind = p_kind
           AND l.credential_id = ANY(COALESCE(p_credential_ids, ARRAY[]::uuid[]))
           AND l.tenant_id = p_tenant_id
           AND p_tenant_id IS NOT DISTINCT FROM
               NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
         RETURNING 1
    )
    SELECT count(*) FROM deleted
$$;

CREATE OR REPLACE FUNCTION pretenant_consume_credential(
    p_kind text,
    p_token_hash bytea,
    p_tenant_id uuid
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH consumed AS (
        UPDATE public.credential_locators AS l
           SET consumed_at = COALESCE(l.consumed_at, now())
         WHERE l.credential_kind = p_kind
           AND l.token_hash = p_token_hash
           AND l.tenant_id = p_tenant_id
           AND l.revoked_at IS NULL
           AND l.consumed_at IS NULL
           AND l.replaced_at IS NULL
           AND p_tenant_id IS NOT DISTINCT FROM
               NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
         RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM consumed)
$$;

CREATE OR REPLACE FUNCTION pretenant_rotate_credential(
    p_kind text,
    p_old_hash bytea,
    p_new_hash bytea,
    p_tenant_id uuid
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    WITH rotated AS (
        UPDATE public.credential_locators AS l
           SET token_hash = p_new_hash
         WHERE l.credential_kind = p_kind
           AND l.token_hash = p_old_hash
           AND l.tenant_id = p_tenant_id
           AND l.revoked_at IS NULL
           AND l.consumed_at IS NULL
           AND l.replaced_at IS NULL
           AND p_tenant_id IS NOT DISTINCT FROM
               NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
         RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM rotated)
$$;

-- The old locator is the global lock point for concurrent IdP callbacks. The
-- detailed predecessor may be in a different tenant silo; making its locator
-- inactive is sufficient to make every future lookup fail before that silo is
-- opened. The new detailed row is inserted in the caller's tenant transaction.
CREATE OR REPLACE FUNCTION pretenant_replace_session_locator(
    p_old_hash bytea,
    p_legacy_old_hash bytea,
    p_new_id uuid,
    p_new_hash bytea,
    p_new_tenant_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    predecessor record;
    found_predecessor boolean := false;
    already_inactive boolean := false;
BEGIN
    IF p_new_tenant_id IS DISTINCT FROM
       NULLIF(current_setting('probectl.tenant_id', true), '')::uuid THEN
        RETURN false;
    END IF;

    FOR predecessor IN
        SELECT l.token_hash, l.revoked_at, l.consumed_at, l.replaced_at
          FROM public.credential_locators AS l
         WHERE l.credential_kind = 'session'
           AND (
                l.token_hash = p_old_hash
                OR (p_legacy_old_hash IS NOT NULL AND l.token_hash = p_legacy_old_hash)
           )
         ORDER BY l.token_hash
         FOR UPDATE
    LOOP
        found_predecessor := true;
        already_inactive := already_inactive
            OR predecessor.revoked_at IS NOT NULL
            OR predecessor.consumed_at IS NOT NULL
            OR predecessor.replaced_at IS NOT NULL;
    END LOOP;

    IF found_predecessor THEN
        UPDATE public.credential_locators AS l
           SET replaced_at = COALESCE(l.replaced_at, now())
         WHERE l.credential_kind = 'session'
           AND (
                l.token_hash = p_old_hash
                OR (p_legacy_old_hash IS NOT NULL AND l.token_hash = p_legacy_old_hash)
           );
    END IF;

    IF already_inactive THEN
        RETURN false;
    END IF;

    INSERT INTO public.credential_locators (
        credential_kind, credential_id, token_hash, tenant_id
    ) VALUES ('session', p_new_id, p_new_hash, p_new_tenant_id);
    RETURN true;
END
$$;

CREATE OR REPLACE FUNCTION pretenant_sync_agent_revocation(
    p_tenant_id uuid,
    p_agent_id text,
    p_spiffe_id text,
    p_serial text,
    p_not_after timestamptz,
    p_revoked_at timestamptz,
    p_revoked_by text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_tenant_id IS DISTINCT FROM
       NULLIF(current_setting('probectl.tenant_id', true), '')::uuid THEN
        RETURN false;
    END IF;
    INSERT INTO public.agent_identity_revocations (
        tenant_id, agent_id, spiffe_id, serial, not_after, revoked_at, revoked_by
    ) VALUES (
        p_tenant_id, p_agent_id, p_spiffe_id, p_serial, p_not_after,
        p_revoked_at, COALESCE(p_revoked_by, '')
    )
    ON CONFLICT (tenant_id, serial) DO UPDATE
       SET revoked_at = EXCLUDED.revoked_at,
           revoked_by = EXCLUDED.revoked_by
     WHERE agent_identity_revocations.agent_id = EXCLUDED.agent_id
       AND agent_identity_revocations.spiffe_id = EXCLUDED.spiffe_id;
    RETURN true;
END
$$;

CREATE OR REPLACE FUNCTION provider_list_revoked_agent_identities()
RETURNS TABLE(serial text, spiffe_id text, live boolean)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT r.serial, r.spiffe_id, r.not_after > now()
      FROM public.agent_identity_revocations AS r
$$;

-- Transfer every boundary function to the non-login role and expose only the
-- exact call shapes needed by the tenant app/provider role.
ALTER FUNCTION pretenant_register_credential(text, uuid, bytea, uuid)
    OWNER TO probectl_pretenant_auth;
ALTER FUNCTION pretenant_sync_credential(
    text, uuid, bytea, uuid, timestamptz, timestamptz, timestamptz
) OWNER TO probectl_pretenant_auth;
ALTER FUNCTION pretenant_resolve_credential(text, bytea)
    OWNER TO probectl_pretenant_auth;
ALTER FUNCTION pretenant_resolve_credential_id(text, uuid)
    OWNER TO probectl_pretenant_auth;
ALTER FUNCTION pretenant_revoke_credential(text, bytea, uuid)
    OWNER TO probectl_pretenant_auth;
ALTER FUNCTION pretenant_delete_credential_locators(text, uuid[], uuid)
    OWNER TO probectl_pretenant_auth;
ALTER FUNCTION pretenant_consume_credential(text, bytea, uuid)
    OWNER TO probectl_pretenant_auth;
ALTER FUNCTION pretenant_rotate_credential(text, bytea, bytea, uuid)
    OWNER TO probectl_pretenant_auth;
ALTER FUNCTION pretenant_replace_session_locator(bytea, bytea, uuid, bytea, uuid)
    OWNER TO probectl_pretenant_auth;
ALTER FUNCTION pretenant_sync_agent_revocation(
    uuid, text, text, text, timestamptz, timestamptz, text
) OWNER TO probectl_pretenant_auth;
ALTER FUNCTION provider_list_revoked_agent_identities()
    OWNER TO probectl_pretenant_auth;

REVOKE ALL ON FUNCTION pretenant_register_credential(text, uuid, bytea, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION pretenant_sync_credential(
    text, uuid, bytea, uuid, timestamptz, timestamptz, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION pretenant_resolve_credential(text, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION pretenant_resolve_credential_id(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION pretenant_revoke_credential(text, bytea, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION pretenant_delete_credential_locators(text, uuid[], uuid)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION pretenant_consume_credential(text, bytea, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION pretenant_rotate_credential(text, bytea, bytea, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION pretenant_replace_session_locator(
    bytea, bytea, uuid, bytea, uuid
) FROM PUBLIC;
REVOKE ALL ON FUNCTION pretenant_sync_agent_revocation(
    uuid, text, text, text, timestamptz, timestamptz, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION provider_list_revoked_agent_identities() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION pretenant_register_credential(text, uuid, bytea, uuid)
    TO probectl_app;
GRANT EXECUTE ON FUNCTION pretenant_sync_credential(
    text, uuid, bytea, uuid, timestamptz, timestamptz, timestamptz
) TO probectl_app;
GRANT EXECUTE ON FUNCTION pretenant_resolve_credential(text, bytea)
    TO probectl_app;
GRANT EXECUTE ON FUNCTION pretenant_resolve_credential_id(text, uuid)
    TO probectl_app;
GRANT EXECUTE ON FUNCTION pretenant_revoke_credential(text, bytea, uuid)
    TO probectl_app;
GRANT EXECUTE ON FUNCTION pretenant_delete_credential_locators(text, uuid[], uuid)
    TO probectl_app;
GRANT EXECUTE ON FUNCTION pretenant_consume_credential(text, bytea, uuid)
    TO probectl_app;
GRANT EXECUTE ON FUNCTION pretenant_rotate_credential(text, bytea, bytea, uuid)
    TO probectl_app;
GRANT EXECUTE ON FUNCTION pretenant_replace_session_locator(
    bytea, bytea, uuid, bytea, uuid
) TO probectl_app;
GRANT EXECUTE ON FUNCTION pretenant_sync_agent_revocation(
    uuid, text, text, text, timestamptz, timestamptz, text
) TO probectl_app;
GRANT EXECUTE ON FUNCTION provider_list_revoked_agent_identities()
    TO probectl_provider;
REVOKE CREATE ON SCHEMA public FROM probectl_pretenant_auth;

-- Backfill pooled and already-provisioned silo rows. Dynamic identifiers come
-- only from the database catalog; format(%I) quotes them. Conflicts are left
-- untouched so a duplicated hash can never redirect an existing credential to
-- a different tenant.
DO $backfill$
DECLARE
    source_schema text;
    tenant record;
BEGIN
    FOR tenant IN SELECT id, isolation_model FROM public.tenants LOOP
        source_schema := 'public';
        IF tenant.isolation_model = 'siloed'
           AND EXISTS (
               SELECT 1
                 FROM information_schema.schemata
                WHERE schema_name = 't_' || replace(tenant.id::text, '-', '')
           ) THEN
            source_schema := 't_' || replace(tenant.id::text, '-', '');
        END IF;

        EXECUTE format(
            'INSERT INTO public.credential_locators
                 (credential_kind, credential_id, token_hash, tenant_id, replaced_at)
             SELECT ''session'', s.id, s.token_hash, s.tenant_id,
                    NULLIF(to_jsonb(s)->>''replaced_at'', '''')::timestamptz
               FROM %I.sessions AS s
              WHERE s.tenant_id = $1
             ON CONFLICT DO NOTHING',
            source_schema
        ) USING tenant.id;
        EXECUTE format(
            'INSERT INTO public.credential_locators
                 (credential_kind, credential_id, token_hash, tenant_id, revoked_at)
             SELECT ''mcp'', t.id, t.token_hash, t.tenant_id,
                    NULLIF(to_jsonb(t)->>''revoked_at'', '''')::timestamptz
               FROM %I.mcp_tokens AS t
              WHERE t.tenant_id = $1
             ON CONFLICT DO NOTHING',
            source_schema
        ) USING tenant.id;
        EXECUTE format(
            'INSERT INTO public.credential_locators
                 (credential_kind, credential_id, token_hash, tenant_id, revoked_at)
             SELECT ''scim'', t.id, t.token_hash, t.tenant_id,
                    NULLIF(to_jsonb(t)->>''revoked_at'', '''')::timestamptz
               FROM %I.scim_tokens AS t
              WHERE t.tenant_id = $1
             ON CONFLICT DO NOTHING',
            source_schema
        ) USING tenant.id;
        EXECUTE format(
            'INSERT INTO public.credential_locators
                 (credential_kind, credential_id, token_hash, tenant_id, revoked_at)
             SELECT ''otlp'', t.id, t.token_hash, t.tenant_id,
                    NULLIF(to_jsonb(t)->>''revoked_at'', '''')::timestamptz
               FROM %I.otlp_tokens AS t
              WHERE t.tenant_id = $1
             ON CONFLICT DO NOTHING',
            source_schema
        ) USING tenant.id;
        EXECUTE format(
            'INSERT INTO public.credential_locators
                 (credential_kind, credential_id, token_hash, tenant_id, revoked_at, consumed_at)
             SELECT ''agent_enroll'', t.id, t.token_hash, t.tenant_id,
                    NULLIF(to_jsonb(t)->>''revoked_at'', '''')::timestamptz,
                    NULLIF(to_jsonb(t)->>''used_at'', '''')::timestamptz
               FROM %I.agent_enroll_tokens AS t
              WHERE t.tenant_id = $1
             ON CONFLICT DO NOTHING',
            source_schema
        ) USING tenant.id;
        EXECUTE format(
            'INSERT INTO public.agent_identity_revocations
                 (tenant_id, agent_id, spiffe_id, serial, not_after, revoked_at, revoked_by)
             SELECT i.tenant_id, i.agent_id, i.spiffe_id, i.serial, i.not_after,
                    NULLIF(to_jsonb(i)->>''revoked_at'', '''')::timestamptz,
                    COALESCE(to_jsonb(i)->>''revoked_by'', '''')
               FROM %I.agent_identities AS i
              WHERE i.tenant_id = $1
                AND NULLIF(to_jsonb(i)->>''revoked_at'', '''') IS NOT NULL
             ON CONFLICT DO NOTHING',
            source_schema
        ) USING tenant.id;
    END LOOP;
END
$backfill$;
