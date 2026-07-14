# Scheduled backups

Cron examples for the three durable stores — PostgreSQL (control-plane state,
backed up as a `pg_dump` *logical dump*: the SQL-level contents, restorable
into any fresh server) and ClickHouse (high-cardinality events, backed up with
its native server-side `BACKUP` statement), plus the object store (tenant
objects and Ed25519-signed WORM audit segments). The scripts they wrap
(`scripts/backup_*.sh` / `scripts/restore_*.sh`), the restore procedure,
RTO/RPO expectations (**RTO** — how long a restore takes; **RPO** — how much
recent data you can afford to lose), and the recovery drill are in
[`docs/ops/backup-restore.md`](../../docs/ops/backup-restore.md). The restore
path is exercised, not asserted: CI's `backup-drill` job runs a full
seed → backup → wipe → restore → verify cycle (`make backup-restore-drill`) on
every pass and uploads the measured `backup-restore-results` CSV artifact with
the profile name, artifact bytes, RPO seconds, and restore seconds.

**Backups contain tenant data.** Store them encrypted at rest on an
access-controlled volume/bucket inside the operator's own infrastructure —
telemetry, including its backups, never leaves the operator's network (a
[non-negotiable](../../CONTRIBUTING.md#non-negotiables)).
Postgres backups are additionally envelope-encrypted in the dump pipeline by
default (`pg_dump | probectl-control backup-seal > .dump.pbk`), so the raw
tenant database does not land on the backups volume. Plaintext `.dump` output
requires the exact break-glass acknowledgement
`PROBECTL_PLAINTEXT_BACKUP_ACK=allow-plaintext-tenant-backup`.
Filesystem object stores are streamed directly through the same envelope
encryption into `.tar.pbk`; no plaintext tar is written. S3/MinIO copies require
verified HTTPS, server-side encryption, and a destination bucket whose default
Object Lock retention is `COMPLIANCE`.

## Object store / WORM evidence

Filesystem-backed installs use the shipped pair directly:

```sh
PROBECTL_OBJECTSTORE_DIR=/var/lib/probectl/objects \
PROBECTL_BACKUP_KEY_FILE=/secure/probectl/envelope.key \
  ./scripts/backup_objectstore.sh /srv/probectl-backups

PROBECTL_OBJECTSTORE_RESTORE_ACK=replace-objectstore \
PROBECTL_BACKUP_KEY_FILE=/secure/probectl/envelope.key \
  ./scripts/restore_objectstore.sh \
    /srv/probectl-backups/objectstore-<ts>.tar.pbk \
    /var/lib/probectl/objects
```

Restore verifies the `.sha256`, authenticates/decrypts into a sibling staging
directory, then swaps directories. The prior tree remains as
`.pre-restore-<timestamp>` for rollback. Symlinks and special files are refused,
so an archive cannot silently capture data outside the configured root.

For S3 or MinIO, set `PROBECTL_OBJECTSTORE_MODE=s3`, source
`PROBECTL_OBJECTSTORE_S3_URI=s3://live-bucket/prefix`, and pass an off-region
`s3://backup-bucket/prefix` destination. Credentials come only from the normal
AWS credential chain/workload identity. A custom MinIO endpoint must be
`https://`; use `AWS_CA_BUNDLE` for an internal CA. The script never disables
certificate verification. It defaults to `AES256` SSE; select `aws:kms` with
`PROBECTL_OBJECTSTORE_S3_KMS_KEY_ID`. The destination bucket must have default
S3 Object Lock **COMPLIANCE** retention, which prevents even an administrator
from rewriting a signed ledger during its retention window. Restore is an
explicit replacement sync and requires
`PROBECTL_OBJECTSTORE_RESTORE_ACK=replace-objectstore`.

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
15 2 * * * cd /opt/probectl && make build && PROBECTL_CONTROL_BIN=./bin/probectl-control PROBECTL_BACKUP_KEY_FILE=/secure/probectl/envelope.key docker compose -f deploy/compose/dev.yml -f deploy/backup/compose-backup.yml run --rm ch-backup
```

Postgres sealed dumps (`.dump.pbk`, plus a `.sha256` integrity fingerprint)
land in the `backups` volume. ClickHouse sealed backups (`.zip.pbk`, plus
`.sha256`) land there too: the overlay lets ClickHouse create the native zip on
the server's encrypted staging volume, streams that zip through
`probectl-control backup-seal`, then removes the raw staging file. The compose
overlay deliberately fails closed unless it can run `backup-seal` with either
`PROBECTL_ENVELOPE_KEY` or the mounted key file
(`PROBECTL_ENVELOPE_KEY_FILE`/`PROBECTL_BACKUP_KEY_FILE`). ClickHouse's
`BACKUP` statement runs **server-side** — the SQL statement executes inside
the ClickHouse server process, so its first archive lands on the ClickHouse
container's own backups disk — the `chbackups` volume configured by
[`clickhouse-backups.xml`](../compose/clickhouse-backups.xml). It's like
asking the chef to box up your leftovers: the box exists, but it's in *their*
kitchen until you carry it home. The `.zip.pbk` is the artifact to copy
off-box (the restore scripts take the off-box file) and prune to your
retention. Raw `.zip` output exists only behind
`PROBECTL_CLICKHOUSE_BACKUP_ACK=encrypted-clickhouse-backup-target` when both
the staging volume and the off-box target are encrypted operator-controlled
storage.

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
  renders Postgres + ClickHouse + filesystem object-store CronJobs from the
  same digest-pinned images,
  envelope-encrypts the Postgres dump in-pipe and the ClickHouse native zip
  after server-side staging, so only `.dump.pbk` and `.zip.pbk` artifacts are
  retained by default, and is wired by
  `backup.credentialsSecret` plus a backups
  PVC (`backup.persistence.*`; a PersistentVolumeClaim is the cluster's
  request slip for durable disk). Off by default; the strict profile enables it.
  Set `backup.objectStore.sourceClaim` to the existing object-store PVC; it is
  mounted read-only and sealed into `.tar.pbk`. No object-store credential or
  secret value is stored in chart values.
  See [`deploy/helm/`](../helm/README.md).
- **Standalone manifests** — `k8s-cronjob-postgres.yaml` and
  `k8s-cronjob-clickhouse.yaml` for clusters that don't use the chart: adjust
  the namespace, the `probectl-backups` PVC, the `probectl-db-credentials`
  secret, the `probectl-envelope-key` secret, and a `probectl-backup-tools` PVC
  containing an executable `probectl-control` binary to your deployment, then
  `kubectl apply`. The database images are digest-pinned; the tools PVC should
  be populated from the same mirrored/digest-pinned release artifact you run for
  the control plane.
