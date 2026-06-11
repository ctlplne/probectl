# The L/XL scale gate

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
L/XL run on reference hardware is recorded in the tables further down — until
then, treat them as targets, not promises. Change them in
`internal/perf/scale.go` (the `Profiles` function) and this table together so
the two never drift.

| Tier | Shape (full scale) | Ingest floor | Publish p95 ceiling | Noisy-neighbor inflation ceiling |
|---|---|---|---|---|
| S  | 1 tenant × 25 agents | 1,500 results/s | 50 ms | n/a (single-tenant) |
| M  | 8 tenants × 40 agents | 3,000 results/s | 50 ms | ≤ 2× |
| L  | 32 tenants × 100 agents | 10,000 results/s | 100 ms | ≤ 2× |
| XL | 64 tenants × 300 agents | 25,000 results/s | 200 ms | ≤ 2× |

Two subtleties make these numbers honest:

- **The inflation ratio only counts above a materiality floor of 5 ms.** If a
  quiet tenant's latency goes from 50 microseconds to 5 milliseconds that's a
  huge *ratio* but it's just scheduler noise — the experience is still excellent.
  Below the floor, the ratio is ignored; above it, the ≤ 2× ceiling bites. The
  floor is the **same 5 ms in CI and at full scale**, not a loosened CI value.
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
still trips the gate. So CI can enforce the exact same documented floor as
reference hardware, rather than a loosened one. The report records the median
pair's solo p95, under-noise p95, and inflation ratio, plus a hard correctness
verdict AND-ed over every phase of every pair.

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
  M-tier full-stack gate against real Kafka + Prometheus as a second step. A
  regression that breaks an SLO, drops a record, or leaks a tenant fails the
  night's build. It's the standing guard until the full L/XL reference run is
  recorded.
- **Full scale (reference hardware):** `make scale-gate TIER=L` (or `XL`) sets
  `PROBECTL_SCALE=1` and runs the real shape with the absolute SLOs armed. Record
  the numbers here when run:

| Date | Tier | Hardware | Throughput | Publish p95 | Inflation | Verdict |
|---|---|---|---|---|---|---|
| _pending_ | L | _to be recorded_ | — | — | — | — |
| _pending_ | XL | _to be recorded_ | — | — | — | — |

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
latency. Each run namespaces its own tenants, and the gate fails on any SLO
violation, incomplete ingest, or scoping error.

- **CI (every pass):** the `load-smoke` job — S tier at 5% scale against the dev
  compose stack (`make load-test-smoke`). Proves the harness, not the platform.
- **Reference hardware (operator-scheduled):** `make compose-up && make load-test
  TIER=L` (then `XL`). The test logs a `RESULT ROW` line — commit it below; once
  both tiers pass, the SLOs above stop being provisional.

| Date | Tier | Hardware | Throughput (results/s) | Publish p95 | Query p95 | Series confirmed | Verdict |
|---|---|---|---|---|---|---|---|
| _pending_ | L | _to be recorded_ | — | — | — | — | — |
| _pending_ | XL | _to be recorded_ | — | — | — | — | — |

Run against a fresh stack (`make compose-down && make compose-up`): the consumer
reads its topic from the start, and a persistent Prometheus keeps prior runs'
series (the per-run namespace isolates correctness, not disk).

The pooled-Postgres side of multi-tenant isolation under load (RLS cost,
per-tenant query p95) stays covered by the `perf-smoke` integration job
(`DrivePooled`, described in [`architecture.md`](architecture.md)); the fairness
work extends it.

**Honesty notes.** The in-process harness measures only the bus → pipeline → store
path — it excludes network hops, real ClickHouse, and the gRPC agent transport,
which the full-stack `test/` soak covers separately. And CI-scale numbers prove
the gate's *mechanics* only: never quote them as platform capability.
