# migrations/

Sequential, numbered SQL migrations for the control-plane datastores.

## Status (S0)

No migrations exist yet. The first migration — the tenant-first core data model
(`tenants`, the Tenant → Org → Team → Project hierarchy, and `tenant_id` on every
tenant-owned table) — lands in **S2**. The migration runner (a Make target plus
an on-boot apply behind a flag) lands in **S1**.

## Conventions (CLAUDE.md §6)

- One change per file, named `NNNN_description.sql` (e.g. `0001_tenants.sql`),
  applied in ascending numeric order.
- **Idempotent**: use `IF NOT EXISTS`, `ON CONFLICT`, etc. so repeated execution
  is safe.
- **Backward-compatible** for zero-downtime upgrades.
- Every new tenant-owned table carries a non-null `tenant_id` plus the
  appropriate index/partition **from its first migration** — never added later
  (CLAUDE.md §7 guardrail 1).
