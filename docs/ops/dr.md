# Disaster recovery: timed failover drill + RTO/RPO

## What this is

The multi-region model ([multi-region.md](../multi-region.md)) is stateless
control-plane replicas everywhere, backed by **one Postgres writer with
streaming replicas**. A region failover **promotes a standby** to be the new
writer and re-points the writer endpoint behind a split-brain fence. This page
is the drill that **times** that mechanism, plus the table where the measured
numbers live. The step-by-step procedure a human follows during a real failover
is the separate runbook, [region-failover.md](../runbooks/region-failover.md).

> **PROVISIONAL until signed off.** The CI drill below measures the real
> promote-and-accept-writes mechanism continuously, but at dev size on shared
> runners. The representative-environment run — real regions, real WAN
> replication lag, production data volume — and its sign-off are pending. Until
> that row is filled in, treat every RTO/RPO number here as provisional.

## The drill (executed, not aspirational)

```sh
make failover-drill     # DESTRUCTIVE to the dev stack
```

The drill (`scripts/failover_drill.sh` + the `deploy/compose/dr-drill.yml`
overlay) needs `POSTGRES_PASSWORD` set in your `.env` — the replica reuses the
same password the primary stack already requires; there is no embedded default.
It then:

1. boots the dev Postgres (the "writer region"), enables replication, and
   attaches a **streaming replica** (`pg_basebackup -R`, the "standby region") —
   and confirms the replica really is in recovery;
2. runs **continuous client-acked writes** against the primary at a measured
   rate, for a few seconds, to establish a baseline;
3. **`kill -9`s the primary** — a hard region loss, no clean shutdown, so no
   split-brain is even possible (the writer is simply dead);
4. calls `pg_promote()` on the replica. The **RTO clock stops at the first
   successful write** on the promoted node — promotion alone isn't recovery,
   *accepting writes* is;
5. computes **RPO** = the client-acked rows that did not make it to the promoted
   node (async streaming replication's honest loss window), reported in rows and
   in seconds at the measured write rate.

It runs in CI on every run (the `failover-drill` job), so the failover
mechanism — replication hookup, promotion, write-readiness — cannot silently
rot, and it exits non-zero on any divergence. The final line looks like:

```
failover drill: PASS — RTO <ms> (kill → promoted+writable); RPO <n> acked rows (~<s>s at <rate> writes/s)
```

## What the dev drill does NOT measure

It is dev-sized, single-host, and replicates over the LAN loopback. It therefore
**excludes**: WAN replication lag (which widens RPO); DNS/proxy writer
re-pointing and the control-plane fence release (which widen RTO — see
[region-failover.md](../runbooks/region-failover.md)); agent geo-DNS shedding;
and the ClickHouse / object-store regional strategies (those are covered by
replication and backups per [backup-restore.md](backup-restore.md) — restore RTO
is measured by *its* own drill). The representative run measures the full
sequence end to end.

## Measured results

| Date | Environment | Write rate | RTO (kill → writable) | RPO (acked rows lost) | Verdict |
|---|---|---|---|---|---|
| _continuous_ | CI drill (dev compose, single host) | see job log | see job log (typically low seconds) | see job log (typically 0–1 rows) | gate |
| _pending_ | representative multi-region infra | — | — | — | — |

**Sign-off:** RTO/RPO targets reviewed and accepted by ______ on ______ (replace
the PROVISIONAL banner above once both the representative row and this sign-off
are filled in).

## Real-event quick reference

This is the short version; the full procedure is
[region-failover.md](../runbooks/region-failover.md).

1. Confirm the writer region is genuinely lost (during ambiguity the fence
   already refuses writes — split-brain protection).
2. Promote the standby (`pg_promote()`, or your operator/controller's promote).
3. Re-point the writer endpoint (DNS/proxy) and release the fence by stamping
   the new promotion epoch.
4. Verify: a write succeeds; `/readyz` is green in the surviving regions; agents
   re-shed via geo-DNS; ClickHouse / object store follow their regional plan.
5. Record the timeline in the table above. When you rebuild the lost region, the
   `make backup-restore-drill` logic is how you validate the restore into it.
