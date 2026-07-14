# High availability and read-view coherence (RESIL-004)

This page explains, in plain terms, why the shipped production references can
run more than one control-plane replica without serving split-brain read views.

## The one-sentence version

The request and ingest paths stay stateless at any replica count, RAM read
models fan in the full bus stream per replica, and side-effecting background
loops run only on the holder of a fenced PostgreSQL lease.

## Why this exists

The control plane has a **stateless request path plus leased singletons**. Agent
results, flow batches, and device metrics are written straight through to the
TSDB (Prometheus/VictoriaMetrics) and ClickHouse. Any replica answering a query
reads the same shared store, so those answers are identical no matter which
replica you hit. You can scale those paths horizontally with no caveat. A pod
does hold temporary leadership state for a small set of background loops, but
that state is reconstructible and its authority lives in PostgreSQL.

A few features build their serving state by consuming the bus into an
in-process structure and answering queries from that RAM copy:

- topology (`/v1/topology`) — the live adjacency graph,
- latest-result view (`/v1/results/latest`),
- TLS/cert posture (`/v1/tls/posture`),
- endpoint/DEM views.

Those views use per-replica consumer groups. In ELI5 terms: every pod gets its
own copy of the newspaper instead of splitting the newspaper pages between pods.
That means every replica consumes the complete stream and builds the same
tenant-partitioned view. Consumers that create external side effects, such as
incident correlation and SIEM export, keep shared groups so a signal is emitted
once for the cluster.

Threat detections (`/v1/threat/detections`) do not depend on per-replica RAM in
production. The IOC/NDR/TLS consumers write their attributed threat signals into
the tenant-scoped `incident_signals` table while opening/correlating incidents.
The API reads those durable signals inside the caller's tenant RLS scope, so any
replica answers from the same store and still returns the correlated incident id.

## Leased singleton background loops

Some work is driven by a timer or database poll instead of a partitioned bus
message. If every pod ran that work, three replicas could send the same alert or
export the same audit row three times. The control plane therefore uses one
cluster-wide, session-scoped PostgreSQL advisory lock named
`probectl:singleton:control-background`.

The lock holder alone runs:

- alert evaluation,
- SIEM audit polling (the bus-backed SIEM forwarder remains a shared-group
  consumer),
- signed audit WORM export,
- tenant telemetry retention, and
- audit retention.

Every other replica is a **hot standby**: it continues serving requests and
ingest, but retries the non-blocking lock acquisition once per
`PROBECTL_SINGLETON_LEASE_INTERVAL` (default `5s`). On a clean holder shutdown,
the next holder normally starts within one retry interval. PostgreSQL also
releases the session lock if its connection dies.

Migration `0054_cluster_singleton_leases.sql` adds the global
`cluster_singleton_leases` fencing ledger. This is deliberately not a
tenant-owned data table: it contains only cluster coordination metadata, never
tenant telemetry. Each acquisition increments a persistent epoch. Renew and
release operations must match the holder id and epoch, so an old leadership
token fails closed after takeover. The advisory lock is the mutual-exclusion
authority; the row supplies the monotonic fencing identity and operator-visible
timestamps.

The lease owns one dedicated writer-pool connection for its complete leadership
term. `PROBECTL_DATABASE_MAX_CONNS` therefore has a minimum of `2`: one lease
session and at least one connection for real work. Run migrations before an HA
rollout so every replica sees the fencing ledger.

Operational signals are:

- `probectl_cluster_singleton_lease_holder` — `1` on the holder, `0` on a
  standby,
- `probectl_cluster_singleton_lease_epoch` — the local fenced epoch, or `0` on
  a standby,
- `probectl_cluster_singleton_lease_acquisitions_total`, and
- `probectl_cluster_singleton_lease_renew_errors_total`.

Structured logs record standby entry, acquisition with its epoch, lease loss,
and release failure. Alert on no replica reporting holder `1` for longer than
two lease intervals, and investigate any renew-error increase.

## What to do today

| Deployment goal | Safe replica count |
|---|---|
| Ingest throughput / API for TSDB+ClickHouse-backed queries | any (scale freely) |
| Consistent topology, endpoint, latest-result, and TLS posture views | any (per-replica fan-in) |
| Consistent threat detections | any (shared incident-signal store) |
| Timer/database-polled side effects | any (one fenced lease holder; all others hot standby) |

**Update (RESIL-004):** the split is complete for the medium production
reference. Topology, endpoint, latest-result, and TLS posture are pure read
models and use per-replica fan-in. Threat detections are served from the durable
incident-signal store. The side-effecting IOC/NDR/TLS consumers still use shared
consumer groups, so incidents, notifications, and SIEM exports are not replayed
once per replica.

The pragmatic scaling split is unchanged: scale the control plane for API and
consumer availability, and scale Kafka, ClickHouse, and the TSDB for telemetry
volume.

## What's Next

Future work moves more view state into durable stores so restarts rebuild less
from the stream, but that is a warm-start/resilience improvement, not a
cross-replica correctness requirement.

**Reference values (RESIL-004):** `values-medium.yaml` now defaults to
`replicaCount: 3` with `podDisruptionBudget.minAvailable: 2`, matching the
documented medium production HA profile.
