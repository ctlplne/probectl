# Capacity Model

This page is the operator math for right-sizing probectl. The data-plane sizing
page tells you what a starter stack looks like; this page tells you why: how many
tenants and agents a tier is meant to hold, how many telemetry events it should
sustain, how fast retention turns rows into disk, and which signal says "split
the shard now."

The simple mental model is a water tank. Agents and collectors are faucets,
Kafka is the pipe, ClickHouse/Postgres/TSDB are tanks, and retention is the drain.
If faucets add water faster than the pipe or drain can handle, the tank rises.
Scale-out keeps the tank below the line before it spills.

## Capacity By Tier

The tenant and host shapes are the full-scale profiles in `internal/perf` and
`docs/scale-gate.md`. "Hosts" means tenant-bound enrolled agents or collectors.
"Result floor" is the minimum end-to-end synthetic result ingest rate that the
scale gate must sustain at full scale. "Event budget" is the day-2 planning
budget across high-volume planes, especially flow/eBPF. SLO numbers stay
provisional until the `scale-fullstack` RESULT ROW receipts are recorded.

| Tier | Max tenants at SLO | Max hosts / agents at SLO | Result ingest floor | All-plane event budget | Full-stack receipt state |
| --- | ---: | ---: | ---: | ---: | --- |
| S | 1 | 25 | 1,500 results/s | 2,000 events/s | CI/dev smoke only; not a platform promise |
| M | 8 | 320 | 3,000 results/s | 20,000 events/s | Nightly M guard; not an L/XL promise |
| L | 32 | 3,200 | 10,000 results/s | 200,000 events/s | Pending `make scale-fullstack TIER=L` receipt |
| XL | 64 | 19,200 | 25,000 results/s | 1,000,000 events/s | Pending `make scale-fullstack TIER=XL` receipt |

Do not sell or capacity-plan L/XL from the provisional numbers alone. The
`scale-fullstack` receipt is the proof that the real Kafka, Prometheus, and
ClickHouse path held the target percentiles on reference hardware. Until those
rows are committed in `docs/scale-gate.md`, treat the table as a sizing target,
not a guarantee.

## Planning Constants

These constants are deliberately conservative. They are not wire schema limits;
they are the bytes to reserve before buying disks. Re-measure them from your
own retained data once the stack has run for a week, then update the local plan.

| Stored class | Planning bytes per stored row | Primary store | Notes |
| --- | ---: | --- | --- |
| Synthetic result | 1,536 B/result | TSDB plus result views | One result produces three TSDB series in the perf harness: success, duration, and one custom metric. |
| Flow/eBPF record | 512 B/row | ClickHouse | Includes tenant, endpoints, counters, protocol, interface, sampling, and ASN/geo enrichment headroom. |
| Control/event row | 2,048 B/event | Postgres or ClickHouse | Incidents, topology/change/threat/cost events with bounded JSON context. |
| Audit row | 4,096 B/event | Postgres plus WORM export | Hash-chain fields, actor/action/target, JSONB data, indexes, and export headroom. |

If a tenant emits unusually wide labels, many custom metrics, or long event
metadata, multiply the relevant constant by 2 until the first measured
compression report is available.

## Retention Growth

Use this formula for each stored class:

```text
GiB = rows_per_second * 86,400 * retention_days * bytes_per_row * replicas / 1,073,741,824
```

Examples with one replica factor:

| Input rate | Stored class | 1 day | 30 days | 90 days |
| ---: | --- | ---: | ---: | ---: |
| 1,000 rows/s | Synthetic result at 1,536 B | 123.6 GiB | 3.6 TiB | 10.9 TiB |
| 1,000 rows/s | Flow/eBPF at 512 B | 41.2 GiB | 1.2 TiB | 3.6 TiB |
| 100 rows/s | Control/event at 2,048 B | 16.5 GiB | 494.4 GiB | 1.4 TiB |
| 10 rows/s | Audit at 4,096 B | 3.3 GiB | 98.9 GiB | 296.6 GiB |

For replicated stores, multiply by the replica count. For object-store or
backup copies, add that copy separately. Retention is the strongest cost lever:
cutting flow retention from 90 days to 30 days cuts the high-volume ClickHouse
footprint by two-thirds.

## Scale-Out Triggers

Scale when a trigger is sustained for 15 minutes or appears in two consecutive
load waves. A single spike is a page candidate, not an immediate reshard.

| Plane | Trigger | Add capacity when |
| --- | --- | --- |
| Kafka | Producer p95 or consumer lag | Publish p95 exceeds the tier ceiling, lag rises for two waves, or disk is above 70%. Add partitions/brokers before increasing buffers. |
| ClickHouse flow/eBPF | Part pressure or query tail | `active_parts` grows wave-over-wave, insert p95 or flow query p95 exceeds 2s, or disk is above 70%. Add shards before raising retention. |
| TSDB | Remote-write/query tail | Remote-write rejects rise, query p95 exceeds the hot-path target, or series cardinality approaches node memory limits. Add storage/select shards. |
| Postgres | RLS query tail | Pooled tenant query p95 exceeds 250ms in `perf-smoke`, lock waits rise, or CPU stays above 70%. Add read replicas first; split provider/global tables only with a migration plan. |
| Control plane | CPU/RSS/goroutines | CPU stays above 70%, RSS is a staircase during soak, or goroutines/open FDs do not return to baseline. Add stateless replicas and check backpressure first. |

The ELI5 rule: if queues grow, scale the slow consumer; if disks grow, shorten
retention or add storage; if tenant query tails grow, add shards or isolate the
noisy tenant.

## Shard-Split Rules

Split by tenant before splitting by time. Tenant-first splits preserve the outer
security boundary and keep deletion/export math simple.

| Store | Split key | Rule |
| --- | --- | --- |
| Kafka | Tenant bucket and topic namespace | Keep enough partitions that large tenants do not serialize onto one partition. For L and XL, pre-create tenant-bucketed topics and keep replication factor 3 with `min.insync.replicas=2`. |
| ClickHouse pooled | `tenant_id`, then month/day partition | Move the largest tenants to their own shard or database when one tenant accounts for more than 25% of write volume or query cost. Keep `tenant_id` leading the order key. |
| ClickHouse siloed/hybrid | Tenant database or data-plane residency | Assign regulated or noisy tenants to their own database/cluster. Their circuit breaker and row policies stay independent from the pooled plane. |
| TSDB | Tenant label and series hash | Put high-cardinality tenants into their own tenant label shard before raising global series limits. |
| Postgres | Pooled RLS table, then tenant silo | Use pooled RLS until p95/lock triggers hold under realistic load. Move large tenants to a siloed schema/instance only through the tenant residency planner. |
| Object store | Tenant prefix or bucket | Use per-tenant prefixes by default; use per-tenant buckets when legal hold, BYOK, or deletion evidence requires a physical boundary. |

Every split keeps the same rule: tenant scope first, then RBAC. A shard split
that makes cross-tenant reads easier is not a capacity fix; it is a security
regression.

## Receipt Discipline

Capacity rows become verified only when the emitted RESULT ROW lines are copied
into `docs/scale-gate.md`:

```sh
make scale-fullstack TIER=L
make scale-fullstack TIER=XL
```

Until then, use this page to size an initial deployment, reserve disk, and set
alerts, but keep public claims tied to the current receipt state.
