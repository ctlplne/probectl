# Data-plane reference manifests and sizing (OPS-011)

probectl is self-hosted: you run the data tier (Kafka, ClickHouse, Postgres, the
TSDB). This page gives reference sizing keyed to the scale tiers and a day-2
runbook so an operator who isn't the author can stand it up and keep it healthy.
These are starting points — measure against your own ingest and adjust.

## Sizing by tier

The tiers match the scale-gate profiles (`docs/scale-gate.md`). "Agents" is
enrolled agents; "events/s" is sustained bus throughput across all planes.

| Tier | Agents | Events/s | Kafka | ClickHouse | Postgres | TSDB |
|---|---|---|---|---|---|---|
| S (small/all-in-one) | ≤ 25 | ≤ 2k | 1 broker (or NATS/Redis lightweight mode) | 1 node, 4 vCPU / 16 GiB / 200 GiB SSD | 2 vCPU / 4 GiB | in-process or 1 small VM |
| M | ≤ 250 | ≤ 20k | 3 brokers, RF=3 | 3 nodes, 8 vCPU / 32 GiB / 1 TiB NVMe each | 4 vCPU / 16 GiB + replica | VictoriaMetrics 1 node, 8 vCPU / 32 GiB |
| L | ≤ 2.5k | ≤ 200k | 5+ brokers, RF=3, tiered storage | sharded, 6+ nodes, 16 vCPU / 64 GiB / 2 TiB NVMe | 8 vCPU / 32 GiB + HA replica | VM cluster, 3+ nodes |
| XL | 10k+ | 1M+ | 9+ brokers, dedicated ZK/KRaft quorum | sharded + replicated, 12+ nodes | 16 vCPU / 64 GiB + HA | VM cluster, sharded |

Reference operators (manage the stores on Kubernetes):

- **Kafka:** Strimzi (`Kafka`/`KafkaNodePool` CRDs). RF=3 and `min.insync.replicas=2`
  at M+ so a broker loss never loses an acked record (pairs with the
  ack-after-durability ingest path).
- **ClickHouse:** Altinity ClickHouse Operator (`ClickHouseInstallation`).
  Partition by `toYYYYMM` with tenant-led `ORDER BY`; per-tenant TTL via row TTL.
- **Postgres:** CloudNativePG or your managed offering; one synchronous replica
  at M+, WAL archiving on for PITR (see backup-restore.md).
- **TSDB:** VictoriaMetrics cluster (`vmstorage`/`vminsert`/`vmselect`) at M+ for
  horizontal scale and a longer out-of-order window than vanilla Prometheus
  (which matters for store-and-forward drains — see CORRECT-003).

## Day-2 runbook

- **Capacity headroom:** alert at 70% disk on ClickHouse and Kafka volumes;
  high-volume flow data is the first to fill (default 90-day retention, SCALE-016
  — shorten it or add storage before it bites).
- **Backpressure:** the bus sheds at a full in-flight buffer and counts it;
  watch `probectl_bus_shed` and `probectl_bus_handler_errors` (CORRECT-009). A
  rising shed rate means the consumers or stores can't keep up — scale the slow
  tier, don't raise the buffer blindly.
- **Out-of-order rejects:** `probectl_tsdb_remote_write_rejected` climbing means
  late samples are being dropped; widen the TSDB out-of-order window.
- **Rebalances:** size Kafka partitions for at least `TenantBuckets` × large-tenant
  count so one tenant can spread across partitions without hot-spotting.
- **Per-silo isolation:** in siloed/hybrid deployments each tenant ClickHouse has
  its own circuit breaker (SCALE-021) — a single silo outage degrades only that
  tenant; check `probectl_*` breaker metrics per target.

## Connection security

Every store connection supports TLS in transit and is default-on in the
multi-tenant/regulated profiles (CLAUDE.md §7 guardrail 12). Do not run the
data tier on plaintext outside a single-node dev box.
