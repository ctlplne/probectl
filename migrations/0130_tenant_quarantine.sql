-- 0130_tenant_quarantine.sql — D-62: per-tenant quarantine, visible to the
-- provider plane.
--
-- With PROBECTL_SILO_FAILURE_MODE=quarantine, a control-plane replica that
-- cannot prove a siloed or hybrid tenant's isolation targets at startup
-- (residency plane missing or unreachable, reader credential missing, reader
-- scope unproven, silo schema catch-up failed) quarantines only that tenant
-- instead of refusing to start. The refusal itself is in-process, at the
-- routing layer (ee/silo Router + tenancy.InTenant). This table is the
-- provider plane's VIEW of it across replicas: one row per (tenant, replica)
-- the replica's quarantine supervisor holds, refreshed every recheck
-- interval and deleted on release. A one-shot command (mcp-stdio, tokens)
-- also reads it, so it refuses a tenant a live replica has quarantined.
--
-- It is provider-DOMAIN state about a tenant, like tenant_provisioning (0071):
-- it carries no tenant telemetry, so the tenant is referenced by `tenant`, not
-- by a tenant-owned `tenant_id` column, and it is never copied into a silo.
-- The tenant request-path role (probectl_app) gets no privilege at all (the
-- 0007 default-privilege spillover is revoked here, as 0112 did); the boot
-- posture check assertProviderDomainTablesNoAppAccess fails closed if one ever
-- comes back. Its sole reach is probectl_provider under tenancy.InProvider.
--
-- Expand-only and idempotent: a new table, IF NOT EXISTS, no change to an
-- existing one, so release N-1 keeps running against this schema (it never
-- reads the table, and it has no quarantine mode).

CREATE TABLE IF NOT EXISTS tenant_quarantine (
    tenant     uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    replica    text        NOT NULL CHECK (length(replica) BETWEEN 1 AND 200),
    reason     text        NOT NULL CHECK (reason IN (
                               'residency_plane_missing',
                               'residency_plane_unreachable',
                               'reader_credential_missing',
                               'reader_scope_unproven',
                               'silo_schema_catchup_failed',
                               'silo_schema_incomplete')),
    plane      text        NOT NULL DEFAULT '',
    detail     text        NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
    remedy     text        NOT NULL DEFAULT '' CHECK (length(remedy) <= 1000),
    since      timestamptz NOT NULL,
    checked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, replica)
);

REVOKE ALL PRIVILEGES ON tenant_quarantine FROM probectl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_quarantine TO probectl_provider;
