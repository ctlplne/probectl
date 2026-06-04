# probectl performance baseline (S18a)

This is probectl's **checked-in load/perf baseline** — a cheap, repeatable
early-warning system, not a full scale validation. It left-shifts the scaling
assumptions of the core pipeline (and pooled-tenancy cost) to **GA (M6)** so a
regression is caught now, in CI, rather than discovered at the final scale gate
(S48). The harness lives in [`internal/perf`](../internal/perf) and is the
reusable engine that S48 (full L/XL gate) and S-T7 (per-tenant fairness) extend.

The philosophy is a **smoke, not a soak**: the thresholds below have generous
headroom, so the guard trips on an order-of-magnitude regression — a
pooled-cardinality blow-up or a Postgres-RLS-cost problem — and not on ordinary
CI jitter. Serves PRD §5.4 / §7.2.

## What the harness drives

Two drivers exercise the core path **agents → bus → stores → query**:

- **Ingest baseline** (`DriveIngest`, no services) — publishes synthetic probe
  results through the lightweight path (bus → pipeline consumer → TSDB) at a
  defined scale and measures end-to-end throughput and publish latency. It also
  asserts correctness: every result is ingested, and each tenant's series land
  under its own `tenant_id` (no cross-tenant label mixing).
- **Pooled multi-tenant smoke** (`DrivePooled`, against Postgres) — K tenants
  share the pooled stores; every tenant-scoped query is run concurrently
  (mixed-tenant load) and must return **exactly** its own rows. This is the
  isolation-under-load assertion (a cross-tenant leak inflates the count; a
  scoping bug deflates it) and the first place an RLS-cost problem shows up.

## Scenarios (M6 smoke sizes)

| Scenario | Shape | Volume |
| --- | --- | --- |
| Ingest baseline | 4 tenants × 5 agents × 5 tests × 20 results | 2,000 results → 6,000 series |
| Pooled multi-tenant | 20 tenants × 100 rows, 10 query-reps, 16 concurrent | 2,000 rows, 200 tenant-scoped queries |

These are intentionally small (sub-second to a few seconds) so the job stays a
CI smoke. The full L/XL multi-region sizes and the formal noisy-neighbor gate are
**S48**; per-tenant fairness *enforcement* is **S-T7**.

## Regression-guard thresholds

The guard lives in code as `perf.M6Baseline()` and is asserted by the smoke
tests. Update the code and this table together when the numbers move materially.

| Metric | Threshold | Rationale |
| --- | --- | --- |
| Ingest throughput | **≥ 3,000 results/sec** (floor) | lightweight path; catches a ~10–50× regression |
| Pooled query p95 | **≤ 250 ms** (ceiling) | tenant-scoped list under mixed load; catches an RLS-cost blow-up |
| Pooled isolation | **0 mismatches** (hard) | any wrong row count is a correctness failure, never tolerated |

## Recorded numbers

Representative figures from a development run (Apple-class arm64, in-process). CI
runners are slower; the thresholds above carry the headroom for that. Refresh
this section from a green `perf-smoke` CI run when the baseline shifts.

| Metric | Recorded | Threshold | Environment |
| --- | --- | --- | --- |
| Ingest throughput | ~188,000 results/sec (no race); ~50,000 (`-race`) | ≥ 3,000 | dev arm64, memory bus + memory TSDB |
| Ingest publish p95 | ~11 µs | — | dev arm64 |
| Pooled query p50 / p95 / p99 | ~2.4 ms / ~11 ms / ~16 ms | p95 ≤ 250 ms | dev arm64, Postgres 18, 20 tenants × 100 rows, 16 concurrent |
| Pooled query throughput | ~4,600 queries/sec | — | dev arm64, Postgres 18 |
| Pooled isolation | 0 mismatches (200/200 queries correct) | 0 | dev arm64, Postgres 18 |

Throughput is the lightweight single-consumer path; the Kafka/multi-consumer
profile and real-TSDB remote-write numbers are sized at S48.

## Running it

```bash
make perf-smoke          # ingest baseline (no services) + pooled (uses PROBECTL_DATABASE_URL)
```

The ingest baseline needs no services. The pooled smoke uses
`PROBECTL_DATABASE_URL` and **skips** when no database is reachable, so the target
is safe to run locally without the dev stack. In CI the `perf-smoke` job runs
both against a Postgres service. The pooled run also exercises the cross-tenant
isolation property under concurrency, complementing the dedicated
`cross-tenant-isolation` gate.

## Scope / placement notes

- The harness is a **main-module library** (`internal/perf`), not the black-box
  `test/` module — matching how every other integration test in this repo is
  structured (in-module, `integration`-tagged, reaching Postgres via
  `PROBECTL_DATABASE_URL`). The `test/` module stays reserved for the full-stack
  soak at S48.
- **Resource-use capture** (control-plane + store CPU/memory under sustained
  load) is deferred to the S48 soak, where it is meaningful against real
  services; the M6 baseline focuses on the load-bearing early-warning signals —
  throughput, query latency, and isolation correctness.
