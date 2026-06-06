# Backup & restore runbook (U-030)

What is backed up, how, how to restore it, what to expect, and the drill
that proves it — for every probectl datastore.

## What is stateful (and what is deliberately not backed up)

| Store | Holds | Backup? |
|---|---|---|
| **Postgres** | tenants, config/state, RBAC, audit chains, SLOs, incidents | **Yes** — logical `pg_dump` (custom format), nightly |
| **ClickHouse** | flow/path/threat/change/cost events + the `probectl_ch_migrations` ledger | **Yes** — native `BACKUP DATABASE … TO File()`, nightly |
| Prometheus/VictoriaMetrics | metric series | Optional — operational telemetry; rebuildable from retention-window re-ingest. Snapshot API if your org requires it |
| Object store | support bundles, **WORM audit exports (U-041)** | Replicate the bucket; the WORM export is itself the tamper-evident off-DB copy of the provider audit chain |
| Kafka | results/events in transit | No — transit, not a system of record; consumers drain to the stores above |

**Backups contain tenant data.** Encrypt at rest, restrict access, keep them
inside the operator's network (sovereignty, CLAUDE.md §7.2). Treat a backup
volume like the database itself.

## Taking backups

One-shot (any time, e.g. before an upgrade):

```sh
./scripts/backup_postgres.sh   /srv/probectl-backups   # postgres-<db>-<ts>.dump + .sha256
./scripts/backup_clickhouse.sh /srv/probectl-backups   # clickhouse-<db>-<ts>.zip + .sha256
```

Both exec inside the running compose stack (no host client tooling), write
SHA-256 manifests, and copy the artifact **off-box** — the artifact in your
output directory is the thing the restore scripts consume. Override
`COMPOSE_FILE` / `PGUSER` / `CH_USER` etc. for non-dev deployments.

Scheduled: `deploy/backup/` — a compose overlay for host cron and k8s
CronJob examples (digest-pinned images, secret-sourced credentials).
Suggested cadence: nightly, retain 7 daily + 4 weekly; stagger PG and CH.

ClickHouse prerequisite: the server must allow the backup path —
`deploy/compose/clickhouse-backups.xml` (mounted by the dev stack) shows the
`<backups><allowed_path>` drop-in; mount the equivalent plus a `/backups`
volume in production.

At larger tiers, move Postgres to pgBackRest/WAL archiving for PITR and
ClickHouse to incremental `BACKUP … SETTINGS base_backup = …`; the scripts
here are the supported baseline and the drill's contract.

## Restoring

**Both restore scripts are destructive: they drop and recreate the
database.** Stop the control plane first; agents store-and-forward while it
is down.

```sh
# 1. Stop probectl-control (agents buffer; the UI is down from here).
# 2. Verify + restore Postgres (drops + recreates, pg_restore from stdin):
./scripts/restore_postgres.sh   /srv/probectl-backups/postgres-probectl-<ts>.dump
# 3. Verify + restore ClickHouse (copies the artifact back, drops, RESTORE):
./scripts/restore_clickhouse.sh /srv/probectl-backups/clickhouse-probectl-<ts>.zip
# 4. Start probectl-control. Boot re-runs Postgres migrations idempotently;
#    the restored probectl_ch_migrations ledger keeps CH schema state
#    consistent with the restored data (U-046).
# 5. Sanity: /readyz green; a tenant-scoped query returns pre-incident data;
#    audit chain verification passes (the WORM verify job will also re-check
#    the exported provider chain against object storage, U-041).
```

Checksums are verified automatically when the `.sha256` manifest sits next
to the artifact.

## RPO / RTO expectations

| Quantity | Expectation |
|---|---|
| **RPO** | The backup cadence — 24h with the example cron; tighten the schedule (or add WAL archiving) for less. WORM audit exports run on their own interval and are not lost with the DB. |
| **RTO (S tier, dev-sized)** | Minutes. The CI drill measures the real number on every pass and prints `backup Ns, restore Ms` — single-digit seconds at drill size. |
| **RTO (M/L)** | Dominated by ClickHouse volume: budget roughly artifact-size ÷ disk throughput, plus ~2 min of orchestration. Record your measured number below after a production-shaped drill. |

| Date | Environment | Data size | Backup time | Restore time | Notes |
|---|---|---|---|---|---|
| _continuous_ | CI drill (dev compose, marker-sized) | KBs | see job log | see job log | `backup-drill` job, every pass |
| _pending_ | reference hardware (M/L-shaped) | — | — | — | run `make backup-restore-drill` against the loaded stack |

## The drill (executed, not aspirational)

```sh
make backup-restore-drill
```

Seeds nonce-marked rows in **both** stores → backs up → **drops both
databases** → restores from the off-box artifacts → asserts every marker
row (count + nonce) survived, and prints the measured times. It runs
against the dev compose stack, exits non-zero on any divergence, and runs
in CI on every pass (the `backup-drill` job) — so the restore path cannot
silently rot. Run it against staging after any storage-layer change.
