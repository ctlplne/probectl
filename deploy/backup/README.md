# Scheduled backups

Cron examples for the two durable stores — PostgreSQL (control-plane state,
backed up as a `pg_dump` *logical dump*: the SQL-level contents, restorable
into any fresh server) and ClickHouse (high-cardinality events, backed up with
its native server-side `BACKUP` statement). The scripts they wrap
(`scripts/backup_*.sh` / `scripts/restore_*.sh`), the restore procedure,
RTO/RPO expectations (**RTO** — how long a restore takes; **RPO** — how much
recent data you can afford to lose), and the recovery drill are in
[`docs/ops/backup-restore.md`](../../docs/ops/backup-restore.md). The restore
path is exercised, not asserted: CI's `backup-drill` job runs a full
seed → backup → wipe → restore → verify cycle (`make backup-restore-drill`) on
every pass.

**Backups contain tenant data.** Store them encrypted at rest on an
access-controlled volume/bucket inside the operator's own infrastructure —
telemetry, including its backups, never leaves the operator's network (a
[non-negotiable](../../CONTRIBUTING.md#non-negotiables)).
Postgres backups are additionally envelope-encrypted in the dump pipeline by
default (`pg_dump | probectl-control backup-seal > .dump.pbk`), so the raw
tenant database does not land on the backups volume. Plaintext `.dump` output
requires the exact break-glass acknowledgement
`PROBECTL_PLAINTEXT_BACKUP_ACK=allow-plaintext-tenant-backup`.

## Compose (host cron)

`compose-backup.yml` defines one-shot backup services (containers that run a
single dump and exit, rather than staying up) as an overlay — a second compose
file layered over the first — on the
[dev/test stack](../compose/dev.yml). It carries that stack's fixed dev
credentials, so adapt the credentials (or use the Kubernetes paths below) for
anything beyond it. Schedule the services from the host's **crontab** — the
host scheduler's table, where each line is a five-field schedule plus a
command (`0 2 * * *` = minute 0, hour 2, every day):

```cron
# Nightly at 02:00/02:15 — keep PG and CH staggered.
0 2 * * *  cd /opt/probectl && make build && PROBECTL_CONTROL_BIN=./bin/probectl-control PROBECTL_BACKUP_KEY_FILE=/secure/probectl/envelope.key docker compose -f deploy/compose/dev.yml -f deploy/backup/compose-backup.yml run --rm pg-backup
15 2 * * * cd /opt/probectl && docker compose -f deploy/compose/dev.yml -f deploy/backup/compose-backup.yml run --rm ch-backup
```

Postgres sealed dumps (`.dump.pbk`, plus a `.sha256` integrity fingerprint)
land in the `backups` volume. The compose overlay deliberately fails closed
unless it can run `probectl-control backup-seal` with either
`PROBECTL_ENVELOPE_KEY` or the mounted key file
(`PROBECTL_ENVELOPE_KEY_FILE`/`PROBECTL_BACKUP_KEY_FILE`). ClickHouse's
`BACKUP` statement runs **server-side** — the SQL statement executes inside
the ClickHouse server process, so its archives land on the ClickHouse
container's own backups disk — the `chbackups` volume configured by
[`clickhouse-backups.xml`](../compose/clickhouse-backups.xml). It's like
asking the chef to box up your leftovers: the box exists, but it's in *their*
kitchen until you carry it home. Copy artifacts
off-box (the restore scripts take the off-box file) and prune to your
retention.

**ClickHouse backups disk must be writable by the clickhouse user (uid
101).** A freshly created volume mounts root-owned: the dev/compose scripts
fix this with a best-effort root `chmod 1777 /backups` (world-writable with
the sticky bit — the same mode as `/tmp`); in Kubernetes set
the **ClickHouse server pod's** `securityContext.fsGroup: 101` (the group
Kubernetes assigns to mounted volumes, so a non-root pod can write them), or
pre-chown
the PVC, so the `BACKUP`/`RESTORE` statements — which write server-side —
can create their files and lock.

## Kubernetes

In Kubernetes the crontab line becomes a **CronJob** — the cluster-native
object that runs a pod on a schedule. Two supported paths:

- **Helm-managed** — set `backup.enabled=true` on the `probectl` chart. It
  renders Postgres + ClickHouse CronJobs from the same digest-pinned images,
  envelope-encrypts the Postgres dump in-pipe — encrypted while streaming, so
  plaintext never touches the backups volume — and is wired by
  `backup.credentialsSecret` plus a backups
  PVC (`backup.persistence.*`; a PersistentVolumeClaim is the cluster's
  request slip for durable disk). Off by default; the strict profile enables it.
  See [`deploy/helm/`](../helm/README.md).
- **Standalone manifests** — `k8s-cronjob-postgres.yaml` and
  `k8s-cronjob-clickhouse.yaml` for clusters that don't use the chart: adjust
  the namespace, the `probectl-backups` PVC, the `probectl-db-credentials`
  secret, the `probectl-envelope-key` secret, and a `probectl-backup-tools` PVC
  containing an executable `probectl-control` binary to your deployment, then
  `kubectl apply`. The database images are digest-pinned; the tools PVC should
  be populated from the same mirrored/digest-pinned release artifact you run for
  the control plane.
