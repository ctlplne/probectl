# probectl performance baseline

## What this is

This is probectl's **checked-in performance baseline** — a cheap, repeatable
early-warning system that runs in CI, not a full scale validation. Think of it
as a smoke detector, not a fire drill: it exists to catch a regression *now*,
the moment it lands, rather than discovering it later at the full scale gate.

The harness lives in [`internal/perf`](../internal/perf). It is the reusable
engine that the full load gate and the per-tenant fairness work both build on.

The guiding idea is a **smoke, not a soak** (a smoke is a short run proving the
thing basically works; a soak is hours of sustained load hunting slow leaks):
the thresholds below have generous headroom on purpose. The guard is meant to
trip on an *order-of-magnitude* regression — a pooled-tenancy cardinality
blow-up, or a cost problem in Postgres row-level security (RLS — the
database-enforced per-tenant row filter, a predicate every pooled query pays
for) — and to stay quiet through ordinary CI timing jitter. If it goes red,
something is genuinely, badly slower.

## What the harness drives

Two drivers exercise the core path **agents → bus → stores → query**:

- **Ingest baseline** (`DriveIngest`, no services) — publishes synthetic probe
  results through the lightweight path (bus → pipeline consumer → in-memory
  TSDB) at a defined scale, and measures end-to-end throughput and publish
  latency. It also asserts *correctness*: every result is ingested, and each
  tenant's series land under its own `tenant_id` (no cross-tenant label mixing).
- **Pooled multi-tenant smoke** (`DrivePooled`, against Postgres) — K tenants
  share the pooled stores; every tenant-scoped query runs concurrently
  (mixed-tenant load) and must return **exactly** its own rows. This is the
  isolation-under-load assertion (a cross-tenant leak would inflate a count; a
  scoping bug would deflate it), and it is the first place a row-level-security
  cost problem shows up.

## Scenarios (CI smoke sizes)

| Scenario | Shape | Volume |
| --- | --- | --- |
| Ingest baseline | 4 tenants × 5 agents × 5 tests × 20 results | 2,000 results → 6,000 series |
| Pooled multi-tenant | 20 tenants × 100 rows, 10 query-reps, 16 concurrent | 2,000 rows, 200 tenant-scoped queries |

(Each result produces three series — probe success, probe duration, and one
custom metric — which is why 2,000 results become 6,000 series.) These sizes are
intentionally small (sub-second to a few seconds) so the job stays a CI smoke.
The full L/XL multi-region sizes and the formal noisy-neighbor gate live in the
full-stack load gate — see [`scale-gate.md`](scale-gate.md).

User-visible hot paths such as RCA, MCP JSON-RPC, topology, what-if, OTLP ingest,
incident correlation, and Prometheus-compatible reads have their own target
catalog in [`perf-hotpaths.md`](perf-hotpaths.md). That catalog is the p50/p95/p99
and throughput denominator; this page is the cheap smoke baseline underneath it.

## Regression-guard thresholds

The guard is `perf.M6Baseline()` in code, asserted by the smoke tests. Update
the code and this table together when the numbers move materially.

| Metric | Threshold | Rationale |
| --- | --- | --- |
| Ingest throughput | **≥ 3,000 results/sec** (floor) | the lightweight path; catches a ~10–50× regression |
| Pooled query p95 | **≤ 250 ms** (ceiling) | a tenant-scoped list under mixed load; catches a row-level-security cost blow-up |
| Pooled isolation | **0 mismatches** (hard) | any wrong row count is a correctness failure, never tolerated |

(p95 is the 95th percentile — the latency the slowest one-in-twenty query
sees. Percentiles, not averages, because an average hides the unlucky tail a
user actually feels; p50/p99 below are the median and the one-in-a-hundred
tail.)

## Illustrative numbers

The figures below are **illustrative, not guarantees** — they come from one
development run on Apple-class arm64, in-process, and they exist only to show the
*shape* of the headroom behind the thresholds. They are not asserted by any test
(only the floors and ceilings above are), and they will differ on your hardware.
CI runners are slower, which is exactly why the thresholds carry so much room.
Refresh this section from a green `perf-smoke` CI run if the baseline shifts.

| Metric | Observed (dev run) | Threshold | Environment |
| --- | --- | --- | --- |
| Ingest throughput | ~188,000 results/sec (no race); ~50,000 with `-race` | ≥ 3,000 | dev arm64, memory bus + memory TSDB |
| Ingest publish p95 | ~11 µs | — | dev arm64 |
| Pooled query p50 / p95 / p99 | ~2.4 ms / ~11 ms / ~16 ms | p95 ≤ 250 ms | dev arm64, Postgres, 20 tenants × 100 rows, 16 concurrent |
| Pooled query throughput | ~4,600 queries/sec | — | dev arm64, Postgres |
| Pooled isolation | 0 mismatches (200/200 queries correct) | 0 | dev arm64, Postgres |

These are the lightweight single-consumer path. The Kafka / multi-consumer
profile and real-TSDB remote-write numbers belong to the full-stack load gate,
not here.

## Running it

```bash
make perf-smoke          # ingest baseline (no services) + pooled (uses PROBECTL_DATABASE_URL)
```

The ingest baseline needs no services. The pooled smoke uses
`PROBECTL_DATABASE_URL` and **skips** when no database is reachable, so the
target is safe to run locally without the dev stack. In CI the `perf-smoke` job
runs both against a TLS Postgres started for the run (`verify-full`, like
production). The pooled run also exercises the cross-tenant isolation property
under concurrency, complementing the dedicated cross-tenant-isolation gate.

## Scope / placement notes

- The harness is a **main-module library** (`internal/perf`), not the black-box
  `test/` module — matching how every other integration test in this repo is
  structured (in-module, `integration`-tagged, reaching Postgres via
  `PROBECTL_DATABASE_URL`). The `test/` module stays reserved for the full-stack
  soak.
- **Resource-use capture** (control-plane + store CPU/memory under sustained
  load) is deferred to that full-stack soak, where it is meaningful against real
  services. This baseline focuses on the load-bearing early-warning signals —
  throughput, query latency, and isolation correctness.

## Producing the soak + scale-gate rows (SCALE-002 / SCALE-020)

The L/XL scale-gate rows, the 24-hour reduced-L soak row, and the DR sign-off
(OPS-005) are **executed measurements on reference hardware** — they are not
filled from estimates, so the tables stay marked _pending_ until a real run
produces them. The harness to produce each is committed so the runs are
reproducible:

- **Scale gate (SCALE-002):** `make scale-gate TIER=L` and `make load-test TIER=L`
  (then `TIER=XL`) on reference hardware; commit the emitted result row here and
  in `docs/scale-gate.md`.
- **24h soak (SCALE-020):** `DURATION=24h ./scripts/soak.sh` against a brought-up
  stack with the control plane running. It samples RSS, bus buffer/shed/handler-
  error, remote-write rejects, and lag (the CORRECT-009 gauges) on an interval
  into a CSV; summarize the trend (flat RSS = no leak) into the soak row. Wire it
  on the nightly reference-hardware runner.
- **DR / region failover (OPS-005):** run the backup-restore drill and a
  representative 2-region failover; record the measured RPO/RTO into the
  sign-off blocks in `docs/ops/dr.md` and `docs/multi-region.md`.
- **Receipts bundle (TEST-011):** `./scripts/export-receipts.sh` captures the
  branch-protection ruleset, the latest green verify-all receipt, and the
  coverage report into a dated data-room bundle.

These execute outside the build sandbox (they need real services, reference
hardware, and a 24-hour window); this commit lands the reproducible harness, not
fabricated numbers.
