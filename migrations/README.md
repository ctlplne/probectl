# migrations/

Sequential, numbered SQL migrations for the control-plane datastores. The
numbered files in this directory — starting at `0001_baseline.sql` — *are* the
schema; the directory listing is the authoritative sequence.

The files are embedded into the binary (`embed.go`, a `//go:embed *.sql` —
Go's directive that compiles the SQL files into the control-plane executable
itself, so a deployed binary always carries exactly the schema it expects and
the two can never be separated or version-skewed) and applied in ascending
order by the migration runner — either `probectl-control migrate` (one-shot)
or on boot when `PROBECTL_MIGRATE_ON_BOOT=true` — idempotently (safe to run
twice: a re-run converges to the same state instead of erroring), so
re-running is safe.

## Conventions

- One change per file, named `NNNN_description.sql` (e.g.
  `0002_tenancy_core.sql`), applied in ascending numeric order.
- **Idempotent**: use `IF NOT EXISTS`, `ON CONFLICT`, etc. so repeated execution
  is safe.
- **Backward-compatible** for zero-downtime upgrades — the `migration-gate` CI
  job (`make migration-gate`) rejects destructive or blocking changes (drop
  column, type change, rename, adding `NOT NULL`), so release N's schema keeps
  working under release N−1's code during a rolling upgrade.
- **Online / non-locking** (SCHEMA-003) — the gate also rejects DDL that would
  lock a table under live ingestion: a `CREATE INDEX` without `CONCURRENTLY` on
  a pre-existing table, and a validating `ADD CONSTRAINT ... CHECK/FOREIGN KEY`
  without `NOT VALID`. Use the online forms (`CREATE INDEX CONCURRENTLY`;
  `ADD CONSTRAINT ... NOT VALID` then `VALIDATE` in a later release). An
  index/constraint on a table **created in the same migration** is empty and
  therefore safe (the gate allows it). For a confirmed-tiny / operator-scale
  table (not a hot telemetry table), annotate the reviewed exception with a
  `-- lock-ok: <reason>` comment on the statement; a reason-less `-- lock-ok` is
  NOT honored.
- **Concurrent indexes are non-transactional** (SCHEMA-001) — PostgreSQL rejects
  `CREATE INDEX CONCURRENTLY` inside a transaction block, while normal probectl
  migrations intentionally run in a transaction. Any migration that uses a
  concurrent index must put a reviewed, reasoned file-level directive before the
  first SQL statement:

  ```sql
  -- probectl:no-tx: CREATE INDEX CONCURRENTLY is rejected inside a PostgreSQL transaction
  CREATE INDEX CONCURRENTLY IF NOT EXISTS example_tenant_idx ON example (tenant_id);
  ```

  The `migration-gate` rejects a concurrent index without this directive, and
  the runner applies the marked migration outside a transaction while still
  recording it in `schema_migrations`. Keep no-tx migrations idempotent and
  narrow; if the ledger write fails after the DDL succeeds, a re-run must be able
  to converge safely.
- **ClickHouse migrations are gated too** (SCHEMA-001) — the Go-embedded
  `chMigrations()` of every telemetry store (flow / eBPF / OTLP / path) is run
  through `chmigrate.CheckMigrations`, which rejects `DROP TABLE` / `RENAME
  TABLE` unless the migration carries a typed `Destructive: true` +
  `Justification` annotation. The data-preserving dedup rebuilds and the
  re-discoverable-cache path re-partition (SCHEMA-002) carry that annotation;
  any new, unannotated destructive telemetry DDL reddens the build.
- Every new tenant-owned table carries a non-null `tenant_id` plus the
  appropriate index/partition **from its first migration** — never added later.
  This is the schema half of the tenant-isolation rule (see
  [CONTRIBUTING.md → Non-negotiables](../CONTRIBUTING.md#non-negotiables)).

## Rollback policy — forward-only, expand/contract

probectl migrations are **forward-only**: there are no `.down.sql` files, by
deliberate design. Rollback is achieved by rolling *forward* (a new,
higher-numbered migration that reverts the change), not by running a
down-migration — the standard practice for zero-downtime production schemas,
where a blind `down` against live data is more dangerous than a reviewed
forward fix (a down-migration written months earlier knows nothing about the
rows production has accumulated since).

To stay safely reversible, schema changes follow **expand/contract**
(parallel-change):

1. **Expand** — add the new column/table/index in a backward-compatible
   migration (nullable/defaulted, `IF NOT EXISTS`); old code keeps working.
2. **Migrate + deploy** — backfill if needed, then ship the code that uses the
   new shape, in a *separate* release from the expand migration so a binary
   rollback never strands the schema.
3. **Contract** — only once no running version reads the old shape, a later
   migration drops it.

Because every migration is backward-compatible (the convention above, enforced
by `migration-gate`) and applied in ascending, idempotent order, the **previous
binary keeps running against the new schema — so a binary rollback needs no
schema rollback.**

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

**Pre-GA exception (now gate-enforced — SCHEMA-002):** a partitioning change
that must recreate a table (e.g. moving the path tables to a `(tenant_id, day)`
partition) may discard re-discoverable snapshot data. This is no longer a
prose-only claim: the discard is authorized by the typed `Destructive: true` +
`Justification` annotation on the ClickHouse migration, which the migration-gate
checks. The justification must explain why the discarded data is re-discoverable
(a cache), so the exception cannot be silently copied to a true telemetry store.
Upgrade note: crossing the path-store v1→v2 boundary recreates path-discovery
history (it is re-discovered as the platform re-probes).
