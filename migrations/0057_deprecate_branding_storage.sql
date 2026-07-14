-- 0057_deprecate_branding_storage.sql — W11 contract phase for removed
-- per-tenant/provider rebranding.
--
-- The application and provider API stop reading/writing these tables in this
-- release. They intentionally remain present for one full compatibility
-- window so an older binary can run during rolling deploy or rollback. A
-- later release may DROP them only after its minimum-supported predecessor is
-- this release or newer. This is the contract half of expand/contract, not
-- forgotten live storage.
--
-- COMMENT is idempotent and non-blocking; migration 0027 created both tables.

COMMENT ON TABLE tenant_branding IS
  'DEPRECATED 2026-07-14: per-tenant rebranding removed; inert compatibility storage pending a later contract migration';
COMMENT ON TABLE provider_branding IS
  'DEPRECATED 2026-07-14: provider rebranding removed; inert compatibility storage pending a later contract migration';
