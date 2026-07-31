-- 0085_bmp_revocation_reader.sql
-- Least-privilege role assumed by the standalone BMP listener while taking
-- authoritative revocation snapshots. The operator creates a LOGIN principal
-- in its own key domain and grants this NOLOGIN role to it; no credential is
-- created or stored by probectl.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = 'probectl_bmp_revocation_reader'
    ) THEN
        CREATE ROLE probectl_bmp_revocation_reader
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    ELSE
        ALTER ROLE probectl_bmp_revocation_reader
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
    END IF;
END
$$;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public
    FROM probectl_bmp_revocation_reader;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public
    FROM probectl_bmp_revocation_reader;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public
    FROM probectl_bmp_revocation_reader;
REVOKE CREATE ON SCHEMA public FROM probectl_bmp_revocation_reader;

GRANT USAGE ON SCHEMA public TO probectl_bmp_revocation_reader;
GRANT EXECUTE ON FUNCTION public.provider_list_revoked_agent_identities()
    TO probectl_bmp_revocation_reader;
