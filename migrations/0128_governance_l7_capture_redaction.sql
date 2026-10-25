-- 0128: the tenant's L7 capture redaction floor (D-43, refinement 3).
--
-- The loosest L7 redaction mode this tenant's eBPF agents may capture under:
-- '' (no statement: the metadata default), 'length', 'metadata', 'headers' or
-- 'full'. The control plane delivers it to the tenant's agents over the mTLS
-- agent channel (the tenant comes from the certificate) and strips L7 records
-- at ingest down to it. 'headers' and 'full' are explicit opt-ins a tenant admin
-- sets through the core route PUT /v1/ebpf/l7-capture-policy (D-64: a core
-- setting, never license-gated; its single writer), audited on the tenant's
-- chain; the regulated profile refuses both.
--
-- Neither the provider plane's policy upsert (UpsertPolicyTx) nor the ee/
-- governance surface writes this column, so an operator can never loosen a
-- tenant's capture redaction from the provider side. The row is provider-owned (0111 write fence); it is read
-- tenant-scoped under RLS like ai_remote_egress (0037).
--
-- Idempotent + expand-only (CLAUDE.md §6): a defaulted column, so release N-1
-- keeps reading and writing every row unchanged.

ALTER TABLE tenant_governance
    ADD COLUMN IF NOT EXISTS l7_capture_redaction text NOT NULL DEFAULT '';
