-- 0124_provider_audit_prune_grant.sql — TEN-01 follow-up: provider audit
-- retention prunes the WORM-exported prefix of provider_audit_events and
-- advances the durable prune anchor in provider_audit_stream_head, in one
-- provider-role transaction (internal/audit/retention.go). Until the serve
-- login became least-privilege (TEN-01) that transaction ran as the superuser
-- login, so 0024's SELECT, INSERT grant never had to cover the DELETE; as the
-- provider role it does. Tenant audit retention already deletes as the provider
-- role (0029/0045), and the prefix it deletes is verified exported before the
-- anchor moves, so the chain stays tamper-evident.
--
-- Idempotent + expand-only (CLAUDE.md §6).

GRANT DELETE ON provider_audit_events TO probectl_provider;
