# The L/XL/XXL scale gate

This is the test that proves probectl actually holds up at scale — not just that
the unit tests pass. It drives the reference-architecture load profiles against
explicit numeric SLOs (an **SLO** — service-level objective — is a measurable
promise, e.g. "publish p95 stays under 50 ms"; **p95** is the 95th-percentile
latency, the experience of the slowest one-in-twenty request), and critically it
includes a **multi-tenant
"noisy-neighbor" scenario** ("noisy neighbor" is the cloud term for one
tenant's load degrading another's experience — one person sprinting should not
make every other treadmill in the gym drag): a proof that one tenant hammering
the system does not
degrade a quiet tenant's experience (no cross-tenant performance bleed). It is the
same harness as the lighter perf smoke (`internal/perf`) — same drivers, just
bigger shapes and stricter SLOs.

Why a separate, bigger gate? Because the cheap CI smoke proves the *mechanics*
work; this proves the *platform* does, at the tenant counts and throughputs a real
deployment sees.

## The numeric SLOs are provisional — not yet validated at full scale

The numeric SLO targets below are engineering estimates, recorded so the gate is
runnable end to end. They become validated capability numbers only when a full
L/XL/XXL run on reference hardware is recorded in the tables further down — until
then, treat them as targets, not promises. Change them in
`internal/perf/scale.go` (the `Profiles` function) and this table together so
the two never drift.

| Tier | Shape (full scale) | Ingest floor | Publish p95 ceiling | Noisy-neighbor inflation ceiling |
|---|---|---|---|---|
| S  | 1 tenant × 25 agents | 1,500 results/s | 50 ms | n/a (single-tenant) |
| M  | 8 tenants × 40 agents | 3,000 results/s | 50 ms | ≤ 2× |
| L  | 32 tenants × 100 agents | 10,000 results/s | 100 ms | ≤ 2× |
| XL | 64 tenants × 300 agents | 25,000 results/s | 200 ms | ≤ 2× |
| XXL | 100 tenants × 1000 agents | 100,000 results/s | 250 ms | ≤ 2× |

Two subtleties make these numbers honest:

- **The inflation ratio only counts above a materiality floor of 5 ms.** If a
  quiet tenant's latency goes from 50 microseconds to 5 milliseconds that's a
  huge *ratio* but it's just scheduler noise — the experience is still excellent.
  Below the floor, the ratio is ignored; above it, the ≤ 2× ceiling bites. When
  the timing check is armed, the floor is the **same 5 ms in CI and at full
  scale**, not a loosened CI value. The in-process CI run that installs the
  fairness gate uses the timing-independent shed/admit-fraction assertion below
  as its hard noisy-neighbor signal; wall-clock p95 remains the full-scale
  reference-hardware SLO.
- **Correctness has no floor and no scale exemption.** Throughput floors can scale
  down for a CI run, but every quiet-tenant result must always land complete and
  correctly tenant-scoped, no matter what the neighbor does. This is tenant
  isolation, asserted under load.

## The noisy-neighbor scenario

The measurement is a **(solo, noisy) pair**, run back-to-back on the shared pooled
path: first the quiet tenant runs *alone* (its baseline p95), then the *same*
quiet workload runs immediately beside a neighbor flooding the system at 10× the
volume. The inflation ratio is the quiet tenant's under-noise p95 divided by its
solo p95.

The trick that lets this run reliably in CI: it runs **3 pairs and gates on the
median pair**. Here's why that's robust. If the shared CI runner is slow
host-wide, that slowness hits *both* halves of a pair, so the ratio
self-normalizes — like weighing yourself before and after lunch on the same
miscalibrated scale: the scale's error cancels out of the *difference*. If
there's a one-off stall, it poisons at most one pair, and the
median absorbs it. Only *sustained* contention inflates every pair — and that
still trips the timing gate when the timing check is armed. The report records
the median pair's solo p95, under-noise p95, and inflation ratio, plus a hard
correctness verdict AND-ed over every phase of every pair.

**The fairness gate is the primary, timing-independent isolation signal
(SCALE-004).** On the in-process stack the in-memory bus has *microsecond*
latency, so the p95-inflation ratio sits far below the 5 ms materiality floor —
the inflation gate is structurally blind there and cannot, on its own, prove
isolation. So the in-process gate now does the honest thing: it **installs the
per-tenant `fairness.Gate`** the platform actually ships and asserts the gate
**sheds the flooding neighbor** — the neighbor's admitted fraction of its 10×
flood must be materially below 1, while the quiet tenant's results all land
correctly. That assertion is independent of timing, runs on every CI pass, and a
**negative control** (the gate disabled / not installed → the flood is admitted
in full) trips it — so a regression that silently stops wiring the gate fails the
build. The p95-inflation ceiling still applies, but only as the *secondary*
check that arms on reference hardware where latency is material.

**SLO status: UNVERIFIED.** The numeric throughput/latency SLOs remain
PROVISIONAL engineering estimates. They become *verified* only when a full L/XL/XXL
run on reference hardware is recorded in the tables below — that run is the
separate EXC-GATE-01 epic and is **not** performed by this in-process gate. Until
then, treat every absolute SLO number here as unverified; the in-process gate
proves the *gate's machinery* (profiles drive, the fairness gate sheds, isolation
and correctness hold), not the platform's absolute numbers.

## Running it

There are two harnesses, deliberately. An **in-process** one (fast, runs on every
CI pass, exercises the bus → pipeline → store path) and a **full-stack** one (runs
the same profiles through real Kafka and Prometheus). This section is the
in-process gate; the next is the full-stack one.

- **CI (every pass):** `TestScaleGateCI` runs the M tier at 5% scale. This proves
  the *gate* (profiles drive, SLOs evaluate, isolation holds), not the platform —
  the absolute throughput floors do not apply at 5% scale, but correctness and
  material inflation do.
- **The flow (volume) plane:** the drive set also includes the high-volume flow
  plane. `TestScaleGateFlowPlaneCI` (the driver is `internal/perf/flowplane.go`)
  pushes 4× the tier's result count as NetFlow records through the *production*
  `FlowConsumer` (the verify + fairness + enrich seams are identical to runtime)
  and fails on any rejected batch or incomplete storage. Both planes ride the
  same `^TestScaleGate` run, so every invocation below exercises them together.
- **Nightly regression guard:** the `scale-gate-m` job in `nightly.yml` runs
  `make scale-gate-m` — the M tier, both planes, at CI scale — and then the
  M-tier full-stack gates against real Kafka + Prometheus + ClickHouse as a
  second step. A regression that breaks an SLO, drops a record, or leaks a
  tenant fails the night's build. It's the standing guard until the full L/XL/XXL
  reference run is recorded.
- **Full scale (reference hardware):** `make scale-gate TIER=L` (or `XL` / `XXL`) sets
  `PROBECTL_SCALE=1` and runs the real shape with the absolute SLOs armed. Record
  the numbers here when run:

| Date | Tier | Hardware | Throughput | Publish p95 | Inflation | Verdict |
|---|---|---|---|---|---|---|
| _pending_ | L | _to be recorded_ | — | — | — | — |
| _pending_ | XL | _to be recorded_ | — | — | — | — |
| _pending_ | XXL | _to be recorded_ | — | — | — | — |

The same `^TestScaleGate` invocation also logs the fleet-envelope row. This is
the control-plane fan-out proof: every tier registers agents, heartbeats them,
reconnects the fleet, drains bounded offline result batches, and queries every
tenant's fleet counts.

| Date | Tier | Hardware | Registered agents | Heartbeats | Reconnect agents | Drained results | Tenants queried | Verdict |
|---|---|---|---:|---:|---:|---:|---:|---|
| _pending_ | L | _to be recorded_ | — | — | — | — | — | — |
| _pending_ | XL | _to be recorded_ | — | — | — | — | — | — |
| _pending_ | XXL | _to be recorded_ | — | — | — | — | — | — |

## The full-stack load gate

The in-process gate above is fast but, by design, skips the real transports (see
the honesty notes at the end). The full-stack harness (`internal/perf/fullstack.go`)
closes that gap using the *same* tier profiles and SLOs, but end to end: synthetic
agents publish through **real Kafka** (the async producer), the **production
consumer** (retry/DLQ — a **dead-letter queue**, the parking lot where a message
that repeatedly fails processing is kept for inspection instead of being
dropped — plus cardinality caps) remote-writes into a **real
Prometheus**, and the run is then confirmed back *out* of the store with
tenant-scoped PromQL (Prometheus's query language) — checking completeness,
per-tenant scoping, and query
latency. The flow-plane sibling gate publishes `probectl.flow.events` through
the same Kafka stack, drains them with the production `FlowConsumer`, writes
to ClickHouse via `PROBECTL_FLOWSTORE_URL`, then confirms every tenant through
`TopTalkers`. That second gate also asserts ClickHouse insert p95, query p95,
and active-part growth so MergeTree compaction pressure is visible. Each run
namespaces its own tenants, and the gates fail on any SLO violation,
incomplete ingest, scoping error, or unbounded ClickHouse part growth.
The same ClickHouse insert/query ceilings are mirrored in the hot-path catalog
as `hp-flow-clickhouse-insert` and `hp-flow-clickhouse-query`, so the operator
sees the storage-path target beside the served `/v1/flows/*` response target.

- **CI (every pass):** the `load-smoke` job — S tier at 5% scale against the dev
  compose stack (`make load-test-smoke`, real Kafka + Prometheus + ClickHouse).
  Proves the harness, not the platform.
- **Reference hardware (operator-scheduled):** `make compose-up && make load-test
  TIER=L` (then `XL` and `XXL`). The tests log `RESULT ROW` lines for the result
  plane and the flow plane — commit them below; once the selected reference tiers
  pass, the matching SLO rows above stop being provisional.

| Date | Tier | Hardware | Throughput (results/s) | Publish p95 | Query p95 | Series confirmed | Verdict |
|---|---|---|---|---|---|---|---|
| _pending_ | L | _to be recorded_ | — | — | — | — | — |
| _pending_ | XL | _to be recorded_ | — | — | — | — | — |
| _pending_ | XXL | _to be recorded_ | — | — | — | — | — |

| Date | Tier | Hardware | Throughput (flows/s) | Insert p95 | Query p95 | Rows confirmed | Active parts | Verdict |
|---|---|---|---|---|---|---|---|---|
| _pending_ | L | _to be recorded_ | — | — | — | — | — | — |
| _pending_ | XL | _to be recorded_ | — | — | — | — | — | — |
| _pending_ | XXL | _to be recorded_ | — | — | — | — | — | — |

Run against a fresh stack (`make compose-down && make compose-up`): the consumer
reads its topics from the start, and persistent stores keep prior runs' data
(the per-run namespace isolates correctness, not disk).

The pooled-Postgres side of multi-tenant isolation under load (RLS cost,
per-tenant query p95) stays covered by the `perf-smoke` integration job
(`DrivePooled`, described in [`architecture.md`](architecture.md)); the fairness
work extends it.

**Honesty notes.** The in-process scale harness measures only the bus → pipeline
→ store path. The distinct `hp-agent-result-push` receipt in
[`perf-hotpaths.md`](perf-hotpaths.md) covers native gRPC/mTLS agent result push
through the bus flush barrier and result TSDB write at CI scale. Real Kafka,
Prometheus, and ClickHouse are covered by the full-stack gates above, while the
long-running `test/` soak covers endurance. CI-scale numbers prove the gate's
*mechanics* only: never quote them as platform capability.

## Reference-hardware full run + 72h soak (the EXC-GATE-01 runbook)

This is the operator runbook for the single command that promotes the
PROVISIONAL SLOs to committed numbers — `make scale-fullstack`. It runs **both**
harnesses above at full scale, back to back, with the absolute SLOs armed
(`PROBECTL_SCALE=1`): first the in-process scale gate (result + flow planes, the
fleet-envelope fan-out pass, and the noisy-neighbor fairness assertion at the
material 5 ms floor), then the full-stack result load gate end to end through
real Kafka + Prometheus, then the full-stack flow load gate end to end through
real Kafka + ClickHouse. It is **not run in CI** and is **not runnable on a
laptop** — it needs reference hardware (below) because the absolute
throughput/latency SLOs only mean anything on the sizing a real deployment uses.

> **Until rows are recorded in the burst and fleet-envelope tables above, the
> SLOs remain UNVERIFIED / PROVISIONAL** (see the status note near the top).
> `make scale-fullstack` passing on reference hardware — and the result rows
> committed here — is what flips them to committed. Do not edit the SLO numbers
> to "pass"; ratchet only from a recorded run.

### Required reference hardware

The L/XL/XXL profiles are sized for, at minimum:

- **Control plane:** 16 vCPU / 32 GiB, NVMe-backed, on a low-latency LAN to the
  data stores (not a shared CI runner — CI numbers are mechanics-only).
- **Kafka:** a 3-broker cluster (or a single broker provisioned for the tier's
  results/s floor — 10k/s at L, 25k/s at XL, 100k/s at XXL) with TLS in transit.
- **Postgres** (pooled RLS) and **ClickHouse** (flow/eBPF) sized for the tier,
  plus a persistent **Prometheus** with the remote-write receiver enabled.
- For the 72h soak: the same stack left running undisturbed, with host-level
  RSS / file-descriptor / Kafka-lag / ClickHouse-part-count metrics scraped so
  drift is visible.
- **XXL floor:** the XXL run is the committed 100k-agent provider fan-out
  envelope (100 tenants × 1000 agents). It must run on a horizontally scaled
  cluster sized for that floor; a laptop or single shared CI runner can prove
  only the harness mechanics, never the XXL platform claim.

### The command

```sh
# one-time, on the reference host:
make compose-down && make compose-up        # fresh stack (consumer reads from start)

# the full run, per tier — record each RESULT ROW in the tables above:
make scale-fullstack TIER=L
make scale-fullstack TIER=XL
make scale-fullstack TIER=XXL
```

Point it at a real cluster by exporting the brokers / Prometheus instead of the
compose defaults:

```sh
PROBECTL_TEST_KAFKA=broker1:9093,broker2:9093,broker3:9093 \
PROBECTL_PROM_URL=https://prom.internal:9090 \
PROBECTL_FLOWSTORE_URL=https://clickhouse.internal:8123 \
  make scale-fullstack TIER=XXL
```

### The 72h soak (leak / compaction-drift guard)

The scale gate is a *burst* test; the soak is the *endurance* test — it catches
slow leaks (heap, goroutines, file descriptors), Kafka consumer-lag creep, and
ClickHouse part-count / compaction drift that a short run hides. The harness
itself runs a single bounded pass, so the soak is *driven by the operator* — loop
`make scale-fullstack` against one long-lived reference stack for 72 hours while
scraping host + store trend metrics. A minimal driver:

```sh
# 72h of repeated waves against ONE long-lived reference stack (do NOT
# compose-down between waves — the point is to watch drift accumulate):
end=$(( $(date +%s) + 72*3600 ))
while [ "$(date +%s)" -lt "$end" ]; do
  PROBECTL_SCALE=1 PROBECTL_SCALE_TIER=XXL make scale-fullstack TIER=XXL || break
done
# in parallel: scrape control-plane RSS/goroutines/FDs, Kafka consumer lag,
# and ClickHouse active-part count for the full window.
```

Record the soak receipt here. The 24-hour row is the reduced early-warning pass;
the 72-hour row is the committed endurance receipt.

| Date | Tier | Window | Hardware | Waves | RSS/FD drift | Kafka lag | ClickHouse parts | Verdict |
|---|---|---|---|---:|---|---|---|---|
| _pending_ | L | 24h | _to be recorded_ | — | — | — | — | — |
| _pending_ | L | 72h | _to be recorded_ | — | — | — | — | — |
| _pending_ | XL | 72h | _to be recorded_ | — | — | — | — | — |
| _pending_ | XXL | 72h | _to be recorded_ | — | — | — | — | — |

Pass criteria for the soak (record alongside the burst result row):

- **No unbounded growth:** control-plane RSS, goroutine count, and open FDs
  return to baseline between load waves (a sawtooth, not a staircase).
- **No consumer-lag creep:** Kafka lag stays bounded — the consumer keeps up for
  the full window, not just the first hour.
- **No compaction drift:** ClickHouse active part count stays bounded (merges
  keep pace); query p95 at hour 72 is within tolerance of hour 1.
- **Correctness holds throughout:** every quiet-tenant result lands complete and
  correctly tenant-scoped for the entire window (isolation under sustained load).

> The 72h soak requires a continuously-running reference stack and is therefore
> **infrastructure-blocked in this environment** — it is the operator action
> above. The in-process and CI gates prove the *machinery*; this run proves the
> *platform*.
