# High availability and read-view coherence (RESIL-004)

This page explains, in plain terms, why the shipped production references can
run more than one control-plane replica without serving split-brain read views.

## The one-sentence version

Ingest, datastore-backed queries, and the remaining RAM read models are coherent
at any control-plane replica count. RAM read models fan in the full bus stream
per replica; threat detections are read from the durable incident timeline.

## Why this exists

The control plane is stateless for the paths that matter most. Agent results,
flow batches, and device metrics are written straight through to the TSDB
(Prometheus/VictoriaMetrics) and ClickHouse. Any replica answering a query reads
the same shared store, so those answers are identical no matter which replica
you hit. You can scale those horizontally with no caveat.

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

## What to do today

| Deployment goal | Safe replica count |
|---|---|
| Ingest throughput / API for TSDB+ClickHouse-backed queries | any (scale freely) |
| Consistent topology, endpoint, latest-result, and TLS posture views | any (per-replica fan-in) |
| Consistent threat detections | any (shared incident-signal store) |

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
