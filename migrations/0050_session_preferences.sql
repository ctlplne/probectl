-- 0050_session_preferences.sql
-- /v1/me is the real signed-in identity document the UI consumes. Persist the
-- resolved user and tenant display preferences with the server-side session so
-- OAuth callback -> session lookup -> principal -> /v1/me returns one coherent
-- model. The table is global/pre-tenant like the token hash itself; tenant_id
-- remains the tenant boundary carried by the session row.

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS time_zone text NOT NULL DEFAULT 'UTC',
    ADD COLUMN IF NOT EXISTS locale text NOT NULL DEFAULT 'en',
    ADD COLUMN IF NOT EXISTS tenant_time_zone text NOT NULL DEFAULT 'UTC',
    ADD COLUMN IF NOT EXISTS tenant_locale text NOT NULL DEFAULT 'en';
