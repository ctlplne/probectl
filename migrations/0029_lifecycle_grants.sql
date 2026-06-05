-- 0029_lifecycle_grants.sql — S-T5 follow-up: the erase engine's missing
-- provider-role capabilities, surfaced by the live integration run.
--
-- 1) break_glass_grants: 0024 granted the provider role SELECT/INSERT/UPDATE
--    but not DELETE — tenant erasure removes the grants ABOUT the tenant.
-- 2) audit_events: append-only for probectl_app BY DESIGN (0007 — the app
--    role can never rewrite history). Tenant erasure still must remove the
--    erased tenant's chain, so the PROVIDER role gets an explicit, scoped
--    DELETE capability: a dedicated RLS policy + grant. The provider-plane
--    use is exactly one call site (the S-T5 erase engine), and every erasure
--    is itself attested on the SEPARATE provider audit chain first.
--
-- Idempotent + expand-only (CLAUDE.md §6).

GRANT DELETE ON break_glass_grants TO probectl_provider;

DROP POLICY IF EXISTS provider_lifecycle_erase ON audit_events;
CREATE POLICY provider_lifecycle_erase ON audit_events
  FOR ALL TO probectl_provider USING (true) WITH CHECK (true);
GRANT SELECT, DELETE ON audit_events TO probectl_provider;
