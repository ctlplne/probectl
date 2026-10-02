-- TEN-01: provision the least-privilege runtime DB login the control plane
-- serves as. Idempotent. Run by the pg-appuser one-shot as the privileged owner,
-- AFTER migrations create probectl_app. The password comes from the psql
-- variable :'app_password' (safe-quoted), never interpolated into the SQL text.
SELECT 'CREATE ROLE probectl_runtime LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB'
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'probectl_runtime')\gexec
ALTER ROLE probectl_runtime WITH PASSWORD :'app_password';
GRANT probectl_app TO probectl_runtime;
