-- 0033: Advanced data governance (S-EE3, F34).
--
-- tenant_governance holds a tenant's data-governance POLICY: classification
-- overrides + redaction strategy (S-EE3, this sprint) plus the COMPOSED view
-- of retention (S-T5) and residency (S-T2/S-EE2) — enforcement of those stays
-- with their owners; this row records the policy and feeds the redaction seam.
-- BYOK (S-T6) is composed in the governance VIEW from tenant_keys, not stored
-- here.
--
-- Provider-owned governance state: never tenant-scoped beyond RLS-read, never
-- copied into a per-tenant silo schema (added to the silo deny list in core).
--
-- Idempotent + expand-only (CLAUDE.md §6).

CREATE TABLE IF NOT EXISTS tenant_governance (
    tenant_id      uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- Classification overrides: { "<category>": "<class>" } (e.g. hostname->pii).
    classifications jsonb      NOT NULL DEFAULT '{}'::jsonb,
    -- Lowest data class redacted when redaction is active (public<internal<
    -- confidential<pii<restricted). Empty/null = the deployment default (pii).
    redact_from     text       NOT NULL DEFAULT '',
    -- Force the portability export to be redacted (a strict-tenant default).
    redact_export   boolean    NOT NULL DEFAULT false,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      text        NOT NULL DEFAULT '',
    CHECK (redact_from IN ('', 'public', 'internal', 'confidential', 'pii', 'restricted'))
);

-- Tenant-side RLS (a tenant reads its own governance policy) + the explicit
-- provider policy (the resolver reads every tenant's policy; the provider
-- plane writes) — the same sanctioned pattern as tenant_quotas / tenant_fairness.
ALTER TABLE tenant_governance ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_governance FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_governance;
CREATE POLICY tenant_isolation ON tenant_governance
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS provider_governance ON tenant_governance;
CREATE POLICY provider_governance ON tenant_governance
  FOR ALL TO probectl_provider USING (true) WITH CHECK (true);

GRANT SELECT ON tenant_governance TO probectl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_governance TO probectl_provider;

-- The tenant-side self-view permission (admin-seeded, like fairness.read in
-- 0031 and lifecycle.* in 0028).
INSERT INTO permissions (key, description) VALUES
    ('governance.read', 'Read the tenant''s own data-governance policy (classification, redaction, retention, residency)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_key)
    SELECT r.tenant_id, r.id, 'governance.read'
    FROM roles r
    WHERE r.tenant_id = '00000000-0000-0000-0000-000000000001'
      AND r.slug = 'admin'
ON CONFLICT (role_id, permission_key) DO NOTHING;
