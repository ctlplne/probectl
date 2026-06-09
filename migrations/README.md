# migrations/

Sequential, numbered SQL migrations for the control-plane datastores.

## Status

44 sequential migrations (`0001_baseline.sql` … `0044_auth_provider_rls.sql`)
define the control-plane schema. They are embedded into the binary (`embed.go`,
a `//go:embed *.sql`) and applied in ascending order by the migration runner —
either `probectl-control migrate` (one-shot) or on boot when
`PROBECTL_MIGRATE_ON_BOOT=true` — idempotently, so re-running is safe.

## Conventions (CLAUDE.md §6)

- One change per file, named `NNNN_description.sql` (e.g.
  `0002_tenancy_core.sql`), applied in ascending numeric order.
- **Idempotent**: use `IF NOT EXISTS`, `ON CONFLICT`, etc. so repeated execution
  is safe.
- **Backward-compatible** for zero-downtime upgrades.
- Every new tenant-owned table carries a non-null `tenant_id` plus the
  appropriate index/partition **from its first migration** — never added later
  (CLAUDE.md §7 guardrail 1).

## Rollback policy — forward-only, expand/contract

probectl migrations are **forward-only**: there are no `.down.sql` files, by
deliberate design. Rollback is achieved by rolling *forward* (a new,
higher-numbered migration that reverts the change), not by running a
down-migration — the standard practice for zero-downtime production schemas,
where a blind `down` against live data is more dangerous than a reviewed
forward fix.

To stay safely reversible, schema changes follow **expand/contract**
(parallel-change):

1. **Expand** — add the new column/table/index in a backward-compatible
   migration (nullable/defaulted, `IF NOT EXISTS`); old code keeps working.
2. **Migrate + deploy** — backfill if needed, then ship the code that uses the
   new shape, in a *separate* release from the expand migration so a binary
   rollback never strands the schema.
3. **Contract** — only once no running version reads the old shape, a later
   migration drops it.

Because every migration is backward-compatible (§6) and applied in ascending,
idempotent order, the **previous binary keeps running against the new schema —
so a binary rollback needs no schema rollback.**

### Manual rollback procedure (operator)

Undoing a *specific* migration is rare — prefer a forward fix. When it's
unavoidable:

1. **Destructive changes** (a dropped column/table): the data is gone under a
   forward-only model, so a **point-in-time restore** from an encrypted backup
   (see `docs/ops/backup-restore.md` and `docs/hardening.md`) is the supported
   recovery — never hand-edit production schema.
2. **Additive changes**: author a forward revert — a new `NNNN_revert_*.sql`
   that `DROP ... IF EXISTS`-es what the bad migration added, reviewed and
   applied like any migration.
3. **Never edit an already-applied migration file in place** — the numbered
   sequence is an append-only ledger; rewriting it desyncs deployed
   environments.

**Pre-GA exception:** a partitioning change that must recreate a table (e.g.
moving the path tables to a `(tenant_id, day)` partition) may discard
re-discoverable snapshot data, recorded in that migration's comment — explicit,
and pre-1.0 only.
