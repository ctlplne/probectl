# Multi-region / active-active HA

probectl runs **active-active across regions** — but it's worth being precise
about what that phrase does and does not mean here, because it's the source of
most confusion about HA databases. (**HA** — high availability: the property
that the service survives a machine, or here a whole region, dying.
**Active-active** means every region serves real traffic all the time, as
opposed to active-passive, where a standby region idles until disaster.)

- The **control-plane tier is active everywhere**: every region runs
  interchangeable, *stateless* control-plane and ingest replicas — stateless
  meaning a replica holds no durable data of its own, so any replica can serve
  any request and killing one loses nothing — all serving
  traffic at the same time.
- The **database is single-writer with read replicas**: durable state is one
  PostgreSQL primary (the writer), with streaming replicas in the other regions
  (**streaming replication** — the primary ships its write log to each replica
  in near-real-time, so replicas trail it by seconds at most).

That split is deliberate and it's the *honest* Postgres model. There is exactly
one writable primary at any instant — which is the correct, conflict-free design
for PostgreSQL. A multi-writer global database (the CockroachDB/Yugabyte style) is
explicitly out of scope. On failover, a standby is promoted and the writer
endpoint re-points to it; during that transition the control plane **fences
writes** so a split-brain situation can never corrupt state. (Fencing is explained
in detail below — it is the safety core of this whole design.)

**Edition note:** the *mechanics* and these docs are **core/free** — stateless
replicas are inherent to how the control plane is built, and the split-brain
fence protects any deployment, single-region or not. What's an Enterprise
entitlement (`ha_support`) is the *validated failover runbooks and support*, not
the code.

---

## Topology

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
    agentsA["agents<br/>(geo-DNS)"] --> CA
    agentsB["agents"] --> CB

    subgraph RA["Region A — writer (active)"]
        CA["control / ingest replicas"]
        PGA[("Postgres PRIMARY")]
        CA -->|writer pool| PGA
        CA -.->|read pool| RLA[("local replica (optional)")]
    end

    subgraph RB["Region B — standby (active ingest)"]
        CB["control / ingest replicas"]
        RLB[("Postgres REPLICA")]
        CB -->|read pool| RLB
    end

    CB -->|"writes → writer endpoint (DNS / proxy)"| PGA
    PGA ==>|streaming replication| RLB
    PGA -. "on failover: endpoint re-points; B's REPLICA is promoted to PRIMARY" .-> RLB
```

- **Regional ingest:** agents connect to the nearest region (**geo-DNS** — DNS
  that answers each client with the nearest region's address — or their
  configured endpoint). Each region's replicas ingest locally. A region outage
  sheds its agents to the next-nearest region. **Be precise about what "converges"
  here:** the **metadata database (Postgres)** streams to the standby region, so
  durable *state* (tenants, tests, RBAC, incidents) carries over with a seconds-scale
  RPO. The **telemetry store (ClickHouse)** ships with a **single-node MergeTree by
  default — it does NOT replicate cross-region**; its regional RPO equals the
  backup cadence unless the operator runs ClickHouse replication (see
  [Telemetry-store regional DR](#telemetry-store-regional-dr-clickhouse) below).
- **Writer endpoint:** a single DNS name / proxy (e.g. a managed-DB failover
  endpoint, Patroni + a VIP, or PgBouncer/HAProxy tracking the leader) that
  always resolves to the current primary. `PROBECTL_DATABASE_URL` points here.
- **Read endpoint (optional):** `PROBECTL_DATABASE_READ_URL` points at the
  local replica for read locality. Reads route there; writes always go to the
  writer endpoint. (Read-routing is opt-in per query path via `DB.ReadPool()`;
  by default reads use the writer, so nothing breaks if unset.)

## Replication model & RPO

**RPO** — recovery point objective — is the amount of just-committed data you
can lose in a failover, measured in time: an RPO of five seconds means at most
the last five seconds of writes may vanish.

**The HA RPO/RTO numbers in this section describe the metadata database
(Postgres) only.** That is the tier with streaming replication and the
seconds-scale failover. The telemetry store (ClickHouse) has a *different,
backup-cadence* RPO unless you opt into replication — see
[Metadata vs telemetry: the RPO asymmetry](#metadata-vs-telemetry-the-rpo-asymmetry).

The Postgres replication mode sets the achievable metadata RPO. probectl behaves
identically either way — it is a deployment choice:

| Mode (`PROBECTL_REPLICATION_MODE`) | RPO | Trade-off |
|---|---|---|
| `sync` | **0** — no committed data lost on failover | higher write latency (commit waits for a standby) |
| `async` (default) | ≈ replication lag at the moment of failure | lower write latency; a small bounded data-loss window |

Replica lag is observable: `/readyz` reports `cluster.reader.lag_seconds` and
the metric `probectl_cluster_replica_lag_seconds{region=…}`. For an RPO-0
guarantee, run `sync` with at least one synchronous standby.

## Split-brain fencing (the safety core)

"Split-brain" is the nightmare of any failover system: two nodes both believe
they are the primary and both accept writes, silently diverging. probectl's
defense is an app-layer **fence** — *fencing* is refusing to let a
possibly-confused node touch shared state — that refuses to write unless the
target is
*provably* the current primary. The control plane probes the writer endpoint
every 5 seconds and **fails writes closed** (HTTP 503 `writer_unavailable`, with a
`Retry-After`) whenever it can't prove that — while **reads keep serving** and
**telemetry ingest never pauses**. The principle: degrade to read-only, never lose
or corrupt data.

There are two specific failure modes it catches:

1. **The writer endpoint points at a read-only standby** — a half-finished
   failover. Detected directly by `pg_is_in_recovery()` returning true.
2. **The writer endpoint points at a stale ex-primary** — an old primary that got
   partitioned off but is still in primary-role and would happily accept writes.
   This is caught by a monotonic **promotion epoch** — *monotonic* meaning it only
   ever increases — stored in the `cluster_state`
   table. Every promotion calls the `cluster_promote(region)` function, which bumps
   the epoch, and that new epoch replicates out to the standbys. A replica that
   already follows the *new* primary carries the higher epoch — so a writer
   endpoint still pointing at the *old* primary (lower epoch) is detected as stale
   and fenced. The epoch works like a reign number: each coronation increments
   it, the new number propagates through the kingdom, and a decree stamped with
   an old reign number is void on sight — an ex-king cannot resume ruling merely
   because he still wears a crown. Because the epoch is a monotonic high-water
   mark, a lower epoch can
   **never** reclaim the writer role.

This fence is the application-layer complement to whatever failover controller you
actually run (Patroni, a managed database, etc.): even if your endpoint briefly
resolves to the wrong node mid-flip, probectl will not write to it.

## RTO

**RTO** — recovery time objective — is how long until writes flow again after a
failure. Here, RTO = failover detection + standby promotion + writer-endpoint repoint +
probectl re-probe (≤ one 5s cycle). The dominant terms are your Postgres
failover controller's detection + promotion times. probectl resumes writes
automatically on the next probe once the endpoint resolves to the promoted
primary — no probectl restart required.

## The RPO/RTO targets are provisional — not yet validated

RPO (how much data you can lose) and RTO (how long recovery takes) are *numeric
SLO targets*. The values below are engineering estimates recorded so the
failover gate is runnable end to end — they become committed numbers only once
validated failover runs back them. They are configurable via
`PROBECTL_RPO_SECONDS` / `PROBECTL_RTO_SECONDS` (surfaced together on `/readyz`
and in this table).

| Target | Provisional value | Determined by |
|---|---|---|
| **RPO** | `0` with `sync`; else ≈ lag (target ≤ 5 s) | replication mode + standby health |
| **RTO** | ≤ **60 s** | DB failover controller detect+promote + a 5 s probe |

## Metadata vs telemetry: the RPO asymmetry

probectl has **two durable stores with two different regional-DR stories**, and
honesty about the gap matters more than a tidy claim:

| Store | What it holds | Cross-region default | Regional RPO (default) | How to tighten |
|---|---|---|---|---|
| **Postgres (metadata)** | tenants, tests, RBAC, audit, SLOs, incidents, cluster state | **streaming replication** (this doc) | `0` with `sync`, else ≈ replica lag (target ≤ 5 s) | run `sync` with a synchronous standby |
| **ClickHouse (telemetry)** | flow, eBPF, OTLP, threat, change, cost rows | **NONE — single-node `MergeTree`** (`values.yaml`) | **≤ 24 h** with the shipped nightly off-region backup profile, plus copy lag | tighten the CronJob schedule, use ClickHouse incrementals, or run ClickHouse replication |
| **Object store** | support bundles, exports, large artifacts | per the operator's bucket replication | bucket-dependent | enable cross-region bucket replication |

So a region loss recovers the *control plane and its state* in seconds, but the
**telemetry written since the last off-region backup is lost** — that window is
your telemetry RPO. This is a deliberate trade (replicating high-cardinality
ClickHouse globally is expensive and often residency-restricted), but it must not
be papered over: the metadata seconds-RPO does **not** extend to telemetry.

### Telemetry-store regional DR (ClickHouse)

Two supported paths, in increasing cost/RPO-tightness order:

1. **Off-region backup (default).** The shipped topology is a single-node
   `MergeTree` plus the ClickHouse regional DR profile in
   [`backup-restore.md`](ops/backup-restore.md#telemetry-regional-dr-profile-off-region-clickhouse-backups).
   Regional telemetry RPO is **≤ 24 h** with the shipped nightly
   `backup.clickhouse.schedule: "30 2 * * *"` plus off-region copy lag; shorten
   it by running the CronJob more often or by using ClickHouse incremental
   backups (`BACKUP ... SETTINGS base_backup = ...`) into the same off-region
   vault. The recovery path on a region loss is: stand up ClickHouse in the
   surviving region, restore the most recent off-region backup, and re-point the
   control plane's ClickHouse host. The `backup-drill` CI job proves this path
   with tenant-scoped ClickHouse marker rows restored from the off-box artifact.
2. **Operator-run ClickHouse replication (config-gated, opt-in).** Convert the
   telemetry tables to `ReplicatedMergeTree` backed by a ClickHouse Keeper /
   ZooKeeper quorum spanning regions, so committed rows replicate with a
   seconds-scale RPO like Postgres. probectl does not ship this topology, but it
   does not get in the way: the schema is engine-agnostic and the store talks the
   standard HTTP interface. This is an operator infrastructure decision (quorum
   placement, residency, cost), not a probectl config flag — track it in your
   own runbook.

Whichever you choose, record the chosen telemetry RPO next to the metadata RPO
in your DR plan so the asymmetry is visible to whoever is on call.

## Per-region data residency

`PROBECTL_RESIDENCY` records the *default* data-residency region for the
deployment. Per-tenant residency is a property of a siloed tenant — a siloed
tenant pins its stores to a region (see [`isolation.md`](isolation.md)). The rule
to internalize: cross-region replication of a residency-restricted tenant's data
must respect that residency. So for a strict tenant, don't replicate its data
globally — use **siloed isolation** with the silo stores confined to the permitted
region.

## Operating it

- **Health/status:** `/readyz` carries the cluster view (region, writer role,
  `writes_usable`, replica lag). The node stays **ready (200) for reads** during a
  failover; `writes_usable: false` tells operators and automation that writes
  paused.
- **Metrics:** `probectl_cluster_writes_usable`, `probectl_cluster_writer_role`
  (writer=1 / reader=0 / stale=-1 / unknown=-2 — alert on `< 1`),
  `probectl_cluster_epoch`, and `probectl_cluster_replica_lag_seconds`, all
  labeled by `region`.
- **Failover:** see [`runbooks/region-failover.md`](runbooks/region-failover.md).
- **Config:** see [`configuration.md`](configuration.md) → "Multi-region / HA".

## Out of scope

A multi-writer global database (CockroachDB/Yugabyte-style); a probectl-operated
hosted SaaS; FedRAMP authorization. The control plane is region-agnostic and
stateless — scaling out a region is adding replicas.

**Cross-region telemetry replication is not shipped.** The default ClickHouse
topology is single-node `MergeTree`; its regional RPO is the off-region backup
cadence (≤ 24 h with the shipped nightly profile), not the metadata's
seconds-scale RPO (see
[the asymmetry section](#metadata-vs-telemetry-the-rpo-asymmetry)). Running
`ReplicatedMergeTree` across regions is an operator decision, not a built-in.
