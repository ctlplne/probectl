-- 0071_tenant_provisioning.sql — resumable publication of isolated tenants.
--
-- Siloed/hybrid setup spans PostgreSQL plus optional ClickHouse planes, so it
-- cannot share one transaction with the tenant registry insert. Keep incomplete
-- work in this provider-only staging table: old and new routers read `tenants`,
-- therefore no tenant is routable until provisioning has completed.
--
-- The row's UUID is the final tenant UUID. A retry reuses it, making every
-- external provisioning leg idempotent. Completion atomically moves the row
-- into `tenants`; failed attempts remain visible to the provider inventory as
-- the derived `provisioning` state without consuming an active tenant band.

CREATE TABLE IF NOT EXISTS tenant_provisioning (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            text NOT NULL UNIQUE,
    name            text NOT NULL,
    isolation_model text NOT NULL
                        CHECK (isolation_model IN ('siloed', 'hybrid')),
    residency       text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Provider lifecycle metadata only; tenant users and the pooled application
-- role receive no access. No tenant telemetry is stored here.
GRANT SELECT, INSERT, DELETE ON tenant_provisioning TO probectl_provider;
