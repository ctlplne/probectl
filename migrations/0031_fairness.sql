-- 0031: Tenant fairness / noisy-neighbor isolation (S-T7, F57).
--
-- tenant_fairness: per-tenant fairness policy overrides (ingest rate bounds,
-- query-cost guards, weight). NULL = unset = the deployment default for that
-- bound (zero/absent means UNLIMITED — fairness is opt-in per bound).
-- Provider-owned platform-protection state, set from the provider plane;
-- tenants may READ their own row (the /v1/fairness self-view — debugging
-- fairness disputes needs the tenant to see its own bounds). On the silo
-- deny list: never copied into tenant schemas.
--
-- fairness.read: the tenant-side permission for the self-view (admin-seeded).
--
-- Idempotent + expand-only (CLAUDE.md §6).

CREATE TABLE IF NOT EXISTS tenant_fairness (
    tenant_id            uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    results_per_sec      double precision,
    flow_events_per_sec  double precision,
    ingest_bytes_per_sec double precision,
    burst_seconds        double precision,
    query_concurrency    integer,
    queries_per_min      double precision,
    weight               integer,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    updated_by           text        NOT NULL DEFAULT '',
    CHECK (results_per_sec      IS NULL OR results_per_sec      > 0),
    CHECK (flow_events_per_sec  IS NULL OR flow_events_per_sec  > 0),
    CHECK (ingest_bytes_per_sec IS NULL OR ingest_bytes_per_sec > 0),
    CHECK (burst_seconds        IS NULL OR burst_seconds        > 0),
    CHECK (query_concurrency    IS NULL OR query_concurrency    > 0),
    CHECK (queries_per_min      IS NULL OR queries_per_min      > 0),
    CHECK (weight               IS NULL OR weight               > 0)
);

-- Tenant-side RLS (a tenant reads its own policy) + the explicit provider
-- policy (the gate reads every tenant's policy; the provider plane writes) —
-- the same sanctioned pattern as tenant_quotas in 0026.
ALTER TABLE tenant_fairness ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_fairness FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_fairness;
CREATE POLICY tenant_isolation ON tenant_fairness
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS provider_fairness ON tenant_fairness;
CREATE POLICY provider_fairness ON tenant_fairness
  FOR ALL TO probectl_provider USING (true) WITH CHECK (true);

GRANT SELECT ON tenant_fairness TO probectl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_fairness TO probectl_provider;

-- The tenant-side self-view permission (admin-seeded, like lifecycle.* in
-- 0028 and security.keys in 0030).
INSERT INTO permissions (key, description) VALUES
    ('fairness.read', 'Read the tenant''s own fairness policy and accounting')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'fairness.read'
    FROM roles r
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug = 'admin'
ON CONFLICT (role_id, permission_key) DO NOTHING;
