# Scheduled backups

Cron examples for the two durable stores — PostgreSQL (control-plane state)
and ClickHouse (high-cardinality events). The scripts they wrap, the restore
procedure, RTO/RPO expectations, and the recovery drill are in
[`docs/ops/backup-restore.md`](../../docs/ops/backup-restore.md).

**Backups contain tenant data.** Store them encrypted at rest on an
access-controlled volume/bucket inside the operator's own infrastructure —
they must never leave the operator's network (CLAUDE.md §7.2 sovereignty).

## Compose (host cron)

`compose-backup.yml` defines one-shot backup services on the dev/compose
network. Schedule them from the host's crontab:

```cron
# Nightly at 02:00/02:15 — keep PG and CH staggered.
0 2 * * *  cd /opt/probectl && docker compose -f deploy/compose/dev.yml -f deploy/backup/compose-backup.yml run --rm pg-backup
15 2 * * * cd /opt/probectl && docker compose -f deploy/compose/dev.yml -f deploy/backup/compose-backup.yml run --rm ch-backup
```

Artifacts land in the `backups` volume; copy them off-box (the restore
scripts take the off-box file) and prune to your retention.

**ClickHouse backups disk must be writable by the clickhouse user (uid
101).** A freshly created volume mounts root-owned: the dev/compose scripts
fix this with a best-effort root `chmod 1777 /backups`; in Kubernetes set
the **ClickHouse server pod's** `securityContext.fsGroup: 101` (or pre-chown
the PVC) so the `BACKUP`/`RESTORE` statements — which write server-side —
can create their files and lock.

## Kubernetes (CronJob)

`k8s-cronjob-postgres.yaml` and `k8s-cronjob-clickhouse.yaml` are standalone
manifests (images digest-pinned to the same versions the compose stack
runs): adjust the namespace, the `probectl-backups` PVC, and the
`probectl-db-credentials` secret to your deployment, then `kubectl apply`.
To fold them into the Helm release, add them under
`deploy/helm/probectl/templates/` guarded by a `backup.enabled` value —
tracked as a follow-up; the manifests here are the supported example.
