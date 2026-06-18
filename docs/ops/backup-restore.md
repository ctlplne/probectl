# Backup & restore runbook

## What this is

probectl keeps its durable state in two databases. A **backup** is a copy of
that state placed where a failure can't reach it; a **restore** is putting the
copy back and getting a working deployment out of it. This runbook is how you
take the copy, how you put it back, how long each takes, and the automated
**drill** — a scheduled rehearsal that performs a real restore and checks the
result — that proves the restore path actually works. The drill matters
because an untested backup is a fire escape you've never walked down: it looks
fine on the wall map right up until the night you need it. Read this page
before you need it — a restore is the kind of thing you do under stress.

## What is stateful (and what is deliberately not backed up)

**Stateful** means the data lives nowhere else — lose the store and it's gone,
which is what makes it worth copying. Anything rebuildable from another source
is deliberately left out: backing it up would only slow down a restore you'll
one day be running under pressure.

| Store | Holds | Backup? |
|---|---|---|
| **Postgres** | tenants, config/state, RBAC, audit chains, SLOs, incidents | **Yes** — logical `pg_dump` (custom format), nightly |
| **ClickHouse** | flow/path/threat/change/cost events + the `probectl_ch_migrations` ledger | **Yes** — native `BACKUP DATABASE … TO File()`, nightly |
| Prometheus/VictoriaMetrics | metric series | Optional — operational telemetry, rebuildable by re-ingesting the retention window. Use the snapshot API if your org requires it. |
| Object store | support bundles, WORM audit exports | Replicate the bucket. WORM = write-once-read-many (appendable, never rewritable); that export is itself the tamper-evident off-database copy of the provider audit chain. |
| Kafka | results/events in transit | No — it's transit, not a system of record. Consumers drain it into the stores above. |

**Backups contain tenant data**, so they are **encrypted at rest by default.**
The chart's Postgres backup CronJob pipes the dump through
`probectl-control backup-seal`, so plaintext never touches the backups volume —
the artifact is a `.dump.pbk` envelope-encrypted container, sealed with the
deployment's at-rest key (the **same** `PROBECTL_ENVELOPE_KEY` as live storage).
**Envelope encryption** means the data is encrypted under a one-off data key,
and that data key is itself wrapped by the deployment's master key (the KEK,
key-encryption key) — so an attacker holding the artifact but not the KEK
holds nothing readable, and a restore on a fresh machine needs exactly one
secret.
ClickHouse's `BACKUP TO File` runs *inside* the ClickHouse server, so it can't
be piped through that filter; it is encrypted by the **backups volume** instead
(the encrypted-volume operator duty in [hardening.md](../hardening.md) §0c, which
`probectl-control preflight --strict` checks). Either way, restrict access to
the backups and keep them inside the operator's network — telemetry never
leaves it (one of the project's
[non-negotiables](../../CONTRIBUTING.md#non-negotiables)).

## Taking backups

One-shot (any time — e.g. right before an upgrade):

```sh
./scripts/backup_postgres.sh   /srv/probectl-backups   # → postgres-<db>-<ts>.dump + .sha256
./scripts/backup_clickhouse.sh /srv/probectl-backups   # → clickhouse-<db>-<ts>.zip  + .sha256
```

Both scripts run the dump *inside* the running compose container (so you need
no Postgres/ClickHouse client on the host), write a SHA-256 manifest next to the
artifact (a **checksum** — a fingerprint that changes if even one byte of the
artifact does, so corruption is caught before a restore starts), and copy the
artifact **off-box** into the output directory you pass — that off-box file is
exactly what the restore scripts consume. Off-box is the point: a backup that
lives on the same disk as the database shares the database's fate. For a non-dev
deployment, override the env vars the scripts read: `COMPOSE_FILE` (default
`deploy/compose/dev.yml`), `PG_SERVICE`/`PGUSER`/`PGDATABASE`, and
`CH_SERVICE`/`CH_USER`/`CH_PASSWORD`/`CH_DB`.

Scheduled backups: `deploy/backup/` has a compose overlay for host cron and k8s
CronJob examples (digest-pinned images, credentials sourced from a secret).
A reasonable cadence: nightly, retain 7 daily + 4 weekly, and stagger Postgres
and ClickHouse so they don't contend (the shipped chart schedules them at 02:00
and 02:30).

**ClickHouse prerequisites.** The server must (1) allow writing backups to its
`/backups` path — `deploy/compose/clickhouse-backups.xml` (mounted by the dev
stack) is the `<backups><allowed_path>` drop-in; mount the equivalent plus a
`/backups` volume in production — and (2) be able to **write** that volume as the
`clickhouse` user (uid 101). A fresh volume mounts root-owned, so the dev/compose
scripts `chmod 1777 /backups` via a best-effort root exec; in Kubernetes set the
ClickHouse server pod's `securityContext.fsGroup: 101` (or pre-chown the PVC)
instead.

At larger scale, move Postgres to pgBackRest / WAL archiving for point-in-time
recovery — the **WAL** (write-ahead log) is Postgres's journal of every change,
so where a nightly dump is a midnight photograph of the house, an archived WAL
is the diary that lets you replay the day and stop at any minute you choose —
and move ClickHouse to incremental `BACKUP … SETTINGS base_backup = …`. The
scripts here are the supported baseline and the contract the drill verifies.

## Restoring

**Both restore scripts are destructive: they drop and recreate the database.**
Stop the control plane first — agents **store-and-forward** (buffer results on
their own disk and replay them once the control plane returns), so no probe
results are lost while it is down.

```sh
# 1. Stop probectl-control. Agents buffer; the UI is down from here.

# 2a. If the Postgres backup is ENCRYPTED (.dump.pbk), decrypt it first. This
#     needs the ORIGINAL envelope key — a fresh node only needs that one key:
PROBECTL_ENVELOPE_KEY=<base64 KEK> \
  probectl-control backup-open < postgres-probectl-<ts>.dump.pbk > postgres-probectl-<ts>.dump

# 2b. Verify + restore Postgres (drops + recreates, pg_restore from stdin):
./scripts/restore_postgres.sh   /srv/probectl-backups/postgres-probectl-<ts>.dump

# 3. Verify + restore ClickHouse (copies the artifact back into the server, drops, RESTORE):
./scripts/restore_clickhouse.sh /srv/probectl-backups/clickhouse-probectl-<ts>.zip

# 4. Start probectl-control. On boot it re-runs the Postgres migrations
#    idempotently; the restored probectl_ch_migrations ledger keeps the
#    ClickHouse schema state consistent with the restored data.

# 5. Sanity-check: /readyz is green; a tenant-scoped query returns pre-incident
#    data; the audit chain verifies (the WORM verify job also re-checks the
#    exported provider chain against object storage).
```

The `backup-open` step is only for the encrypted `.dump.pbk` artifacts the chart
CronJob produces; a plain `.dump` from `backup_postgres.sh` goes straight to
`restore_postgres.sh`. If the `.sha256` manifest sits next to the artifact, both
restore scripts verify it automatically before touching the database, and abort
on mismatch.

### Restoring on Kubernetes (chart-managed restore Jobs)

The compose scripts above are the host/dev path. On Kubernetes the chart ships
one-shot restore Jobs so the restore is reproducible and audited, NOT a manual
`kubectl exec` (OPS-001 for Postgres, OPS-007 for ClickHouse). Postgres reads
its sealed `.pbk` from the chart backups PVC inside the restore Job. ClickHouse
is different: `RESTORE ... FROM File(...)` runs inside the ClickHouse server, so
the `.zip` must already be visible on the ClickHouse server's configured backup
path (`restore.clickhouse.serverBackupPath`, default `/backups`). A PVC mounted
only into the restore Job pod is the wrong filesystem.

```sh
# Postgres — decrypts the sealed .pbk in-pipe (backup-open) then pg_restore:
helm upgrade probectl deploy/helm/probectl --reuse-values \
  --set restore.enabled=true \
  --set restore.backupFile=postgres-probectl-<ts>.dump.pbk

# ClickHouse — server-side RESTORE DATABASE ... FROM File(...) (mirrors the
# CH backup CronJob; the server-visible CH backups volume is encrypted at rest,
# §0c):
helm upgrade probectl deploy/helm/probectl --reuse-values \
  --set restore.clickhouse.enabled=true \
  --set restore.clickhouse.backupFile=clickhouse-probectl-<ts>.zip \
  --set restore.clickhouse.serverBackupPath=/backups

# Each is a Job with backoffLimit 0 (fail loud, never silently retry-and-clobber).
# Watch it to completion, then DISABLE it again so a later upgrade doesn't re-run it:
kubectl logs -f job/probectl-clickhouse-restore
helm upgrade probectl deploy/helm/probectl --reuse-values \
  --set restore.clickhouse.enabled=false
```

## RPO / RTO expectations

- **RPO** (recovery point objective — how much data you can lose) = the backup
  cadence — 24 h with the example nightly cron: a failure just before tonight's
  backup loses everything since last night's. Tighten the schedule (or add WAL
  archiving) for less. The WORM audit exports run on their own interval, so
  they are not lost with the DB.
- **RTO** (recovery time objective — how long a restore takes):
  - *Small / dev-sized:* minutes — usually single-digit seconds at drill size.
    The CI drill measures the real number on every run and prints
    `backup Ns, restore Ms`.
  - *Medium / large:* dominated by the ClickHouse volume — budget roughly
    `artifact size ÷ disk throughput` plus ~2 min of orchestration. Run a
    production-shaped drill and record the number below.

| Date | Environment | Data size | Backup time | Restore time | Notes |
|---|---|---|---|---|---|
| _continuous_ | CI drill (dev compose, marker-sized) | KBs | see job log | see job log | `backup-drill` job, every CI run |
| _pending_ | reference hardware (M/L-shaped) | — | — | — | run `make backup-restore-drill` against the loaded stack |

## The drill (executed, not aspirational)

```sh
make backup-restore-drill
```

This seeds nonce-marked rows in **both** stores (137 rows in Postgres, 251 in
ClickHouse), backs them up, **drops both databases**, restores from the off-box
artifacts, then asserts every marker row survived — both the count *and* the
nonce — and prints the measured backup/restore times. The **nonce** (a one-time
random marker) is what makes the check honest: a row count alone could pass on
leftovers from an earlier run, but only *this* run's rows carry this run's
nonce, so a pass proves the restore really round-tripped today's data. It runs
against the dev compose stack, exits non-zero on any divergence, and runs in CI
on every run (the `backup-drill` job), so the restore path cannot silently rot.
Run it against staging after any storage-layer change.

## Point-in-time recovery (PITR) — WAL archiving (OPS-008)

The nightly logical dump above gives you a daily restore point. For tighter
RPO — recovering to *any* moment, not just the last dump — enable Postgres
continuous WAL archiving. This is a tested recipe, not just a pointer.

What PITR buys you: with a base backup plus the WAL stream, you can replay to a
chosen timestamp (e.g. "the instant before the bad migration"), so your recovery
point objective drops from "up to 24h of loss" to "seconds".

Postgres server settings (set, then restart):

```
wal_level = replica
archive_mode = on
# Archive each completed WAL segment to durable, OFF-host storage. The archive
# MUST be encrypted at rest (it contains tenant data) and MUST NOT live on the
# same volume as the data directory — a disk loss would take both.
# backup-seal is a stdin→stdout encryption filter (it has NO --in/--out flags):
# feed the WAL segment %p on stdin via shell redirection, pipe the sealed bytes
# to durable storage. The KEK comes from PROBECTL_ENVELOPE_KEY (or --key-file).
archive_command = 'probectl-control backup-seal < %p | aws s3 cp - s3://YOUR-BUCKET/wal/%f'
archive_timeout = 60   # force a segment at least every 60s, bounding RPO
```

Take a base backup (also sealed) on a schedule:

```
pg_basebackup -D - -Ft -z -Xnone | probectl-control backup-seal \
  | aws s3 cp - s3://YOUR-BUCKET/base/$(date -u +%Y%m%dT%H%M%SZ).tar.gz.sealed
```

Restore to a point in time:

1. Provision a fresh Postgres data directory.
2. `backup-open` the most recent base backup taken *before* your target time and
   unpack it into the data directory.
3. Create `recovery.signal` and set the recovery target:
   ```
   restore_command = 'aws s3 cp s3://YOUR-BUCKET/wal/%f - | probectl-control backup-open > %p'
   recovery_target_time = '2026-06-12 09:14:00+00'
   recovery_target_action = 'promote'
   ```
4. Start Postgres; it replays WAL up to the target and promotes.
5. Run `probectl-control migrate` (idempotent) and verify `/readyz`, then run the
   backup-restore drill's verify pass against the recovered instance.

**Strict profile:** in regulated deployments WAL archiving is required, not
optional — `archive_mode = on` with a sealed, off-host, encrypted archive and an
`archive_timeout` that meets your RPO. ClickHouse PITR uses its native
`BACKUP ... TO` incrementals to the same off-host, encrypted store (see OPS-011).
