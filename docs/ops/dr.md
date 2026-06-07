# Disaster recovery: timed failover drill + RTO/RPO (U-053)

The multi-region model ([multi-region.md](../multi-region.md)) is stateless
control-plane replicas everywhere with **one Postgres writer + streaming
replicas**; a region failover **promotes a standby** and re-points the
writer endpoint behind the split-brain fence. This page is the drill that
TIMES that mechanism and the table where the numbers live.

> **PROVISIONAL until signed off.** The CI drill below measures the real
> promote-and-accept-writes mechanism continuously, at dev size on shared
> runners. The representative-environment run (real regions, real WAN
> replication lag, production data volume) and its sign-off are
> BLOCKED-ON-HUMAN — until that row is filled, treat all RTO/RPO claims as
> provisional.

## The drill (executed, not aspirational)

```sh
make failover-drill     # DESTRUCTIVE to the dev stack
```

`scripts/failover_drill.sh` + `deploy/compose/dr-drill.yml`:

1. boot the dev Postgres (the "writer region"), enable replication, and
   attach a **streaming replica** (`pg_basebackup -R`, the "standby
   region") — verified to be in recovery;
2. run **continuous acked writes** against the primary at a measured rate;
3. **`kill -9` the primary** (hard region loss — no clean shutdown, no
   split-brain possible because the writer is dead);
4. `pg_promote()` the replica; the **RTO clock stops at the first
   successful write** on the promoted node — promotion alone isn't
   recovery, accepting writes is;
5. **RPO** = client-ACKED rows missing on the promoted node (async
   streaming's honest loss window), reported in rows and seconds at the
   measured write rate.

It runs in CI on every pass (the `failover-drill` job), so the failover
mechanism — replication hookup, promotion, write-readiness — cannot
silently rot. Exit non-zero on any divergence.

## What the dev drill does NOT measure

Dev-size, single-host, LAN-loopback replication. It excludes: WAN
replication lag (widens RPO), DNS/proxy writer re-pointing and the
control-plane fence release (widens RTO; see the failover runbook in
`multi-region.md`), agent geo-DNS shed, and ClickHouse/object-store
regional strategies (covered by replication/backup per
[backup-restore.md](backup-restore.md) — restore RTO measured by its own
drill). The representative run measures the full sequence.

## Measured results

| Date | Environment | Write rate | RTO (kill → writable) | RPO (acked rows lost) | Verdict |
|---|---|---|---|---|---|
| _continuous_ | CI drill (dev compose, single host) | see job log | see job log (typically low seconds) | see job log (typically 0–1 rows) | gate |
| _pending_ | representative multi-region infra | — | — | — | — |

**Sign-off:** ☐ RTO/RPO targets reviewed and accepted by ______ on ______
(replace the PROVISIONAL banner above when both the representative row and
this sign-off are filled).

## Real-event quick reference

1. Confirm the writer region is genuinely lost (the fence refuses writes
   during ambiguity — split-brain protection, `multi-region.md`).
2. Promote the standby (`pg_promote()` / your operator's promote).
3. Re-point the writer endpoint (DNS/proxy); release the fence.
4. Verify: a write succeeds; `/readyz` green in surviving regions; agents
   re-shed via geo-DNS; ClickHouse/object-store per their regional plan.
5. Record the timeline against the table above; run
   `make backup-restore-drill` logic against the new region when restoring
   the lost one.
