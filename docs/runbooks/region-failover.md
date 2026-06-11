# Runbook: region failover

## What this is

Promote a standby Postgres and move the writer to a new region, with **no
split-brain** and **bounded data loss**. The terms, once, before the clock
starts: the **writer** (primary) is the one database accepting changes; a
**standby** is a streaming replica — a continuously updated copy — usually in
another region; **promoting** a standby turns that copy into the new writer;
and **split-brain** is two databases both believing they are the writer and
accepting different writes — the failure this whole runbook is shaped to
prevent. probectl's **fence** is a promotion **epoch**: a counter stored in the
database itself that only ever goes up. Think of it as the deed number on a
house — whoever holds the highest-numbered deed is the owner, and an old
photocopy can't reclaim the property. The conceptual model — why there is
exactly one writer, how the fence works — is [multi-region.md](../multi-region.md);
this is the step-by-step you follow during an actual failover.

**Who runs it:** a DB operator (does the Postgres failover) plus a platform
operator (verifies probectl resumes writes).

**Pre-requisites:** streaming replication is healthy; the writer endpoint is a
DNS name or proxy you can re-point; the `cluster_state` table exists (it is
created by migration `0032_cluster_state.sql`).

## 0. Decide: is a failover warranted?

A failover is for a **primary-region loss** — the primary is down or network-
isolated — not for transient replication lag. Check `/readyz` across regions and
the `probectl_cluster_replica_lag_seconds` metric. If the primary is already
unreachable, probectl will be fencing writes for you (a retryable `503` with the
code `writer_unavailable`), while reads and telemetry ingest keep flowing.

## 1. Confirm the standby is caught up (this sets your RPO)

**RPO** (recovery point objective) is how much just-written data you lose;
**RTO** (recovery time objective, measured in step 5) is how long until writes
work again. The standby's replication lag at the moment of loss *is* your RPO:

- **Synchronous** replication: the synchronous standby has every committed row →
  **RPO 0**.
- **Asynchronous**: check the standby's replay lag at the moment of loss with
  `pg_last_xact_replay_timestamp()`. Anything written inside that lag window may
  be lost — **record it**. If a fresher standby exists, do not promote a badly
  lagged one.

## 2. Promote the standby (DB operator)

Use your Postgres failover tooling: `pg_ctl promote`, Patroni
`switchover`/`failover`, or your managed-DB failover action. After promotion the
new primary is **writable** and on a **new timeline** — Postgres's history fork
counter: promotion branches the history, so anything the old primary might
still write lands on the abandoned branch, not this one.

## 3. Stamp the promotion epoch — this is the fence (do not skip)

On the **newly promoted primary**, run:

```sql
SELECT cluster_promote('<new-writer-region>', '<operator>');
```

This bumps `cluster_state.writer_epoch` by one and records the new writer region
and actor. The new epoch replicates out to the other standbys. **This is the
split-brain fence:** the old primary keeps the *lower* epoch, so probectl
refuses to write to it even if the endpoint briefly points back at it.
Skipping this step risks a split-brain write — **do not skip it.**

## 4. Re-point the writer endpoint

Move `PROBECTL_DATABASE_URL`'s DNS name / proxy to the promoted primary:

- **Managed DB:** usually automatic.
- **Patroni / HAProxy:** tracks the leader for you.
- **Manual DNS:** update the record and wait out the TTL.

The per-region read replicas (`PROBECTL_DATABASE_READ_URL`) keep pointing at
their own local node — reads stay local.

## 5. Verify (platform operator) — the RTO check

probectl re-probes the database every 5 s and resumes writes automatically —
**no restart needed.** Confirm on a replica in a surviving region:

```text
GET /readyz  →  cluster.writes_usable:        true
                cluster.writer.writer_region: <new-writer-region>
                cluster.highest_epoch:        <bumped value>
```

(The cluster view is nested under the `cluster` key of the `/readyz` JSON; the
writer node's reported region is the `writer_region` field on `cluster.writer`.)
A mutating request — e.g. saving a config — should now succeed instead of
returning `503`. The elapsed time from primary loss to `writes_usable: true` is
your realised **RTO**; compare it against `PROBECTL_RTO_SECONDS` (default and
provisional target: 60 s).

## 6. Rebuild the old region as a standby

Bring the former primary back as a **standby** of the new primary (re-clone, or
`pg_rewind` it onto the new timeline — `pg_rewind` unwinds the diverged copy's
history just far enough that it can follow the new branch). It rejoins on the
current epoch. Until it does, probectl correctly fences it (it is either on a
lower epoch or in recovery).

## Watch-outs

- **Never promote two standbys for the same cluster** — there is only ever one
  primary. `cluster_promote` makes the winner unambiguous (highest epoch wins); a
  second promotion that does not also win the endpoint is fenced anyway.
- **Data residency:** do not fail a residency-restricted tenant's data into a
  region its policy forbids. Strict tenants run **siloed** with region-pinned
  stores rather than global replication.
- **A failover is not a backup.** Keep the documented backup / PITR policy
  (recorded in `PROBECTL_BACKUP_RETENTION_NOTE`) regardless — see
  [backup-restore.md](../ops/backup-restore.md).
