# The L/XL scale gate (S48) — the acquirer-grade scale proof

The gate runs the PRD §5.4 reference-architecture load profiles against
numeric SLOs, including the **multi-tenant noisy-neighbor scenario** (F57:
no cross-tenant performance bleed). It extends the S18a harness
(`internal/perf`): same drivers, bigger shapes, explicit SLOs.

## ⚠ The numeric SLOs are PROVISIONAL — sign-off required

CLAUDE.md §2 lists numeric SLO targets as a **human-owned open decision**.
The values below are engineering estimates recorded so the gate is runnable
end to end. They await explicit sign-off; change them in
`internal/perf/scale.go` (`Profiles`) and this table together.

| Tier | Shape (full scale) | Ingest floor | Publish p95 ceiling | Noisy-neighbor inflation ceiling |
|---|---|---|---|---|
| S  | 1 tenant × 25 agents | 1,500 results/s | 50 ms | n/a (single-tenant) |
| M  | 8 tenants × 40 agents | 3,000 results/s | 50 ms | ≤ 2× |
| L  | 32 tenants × 100 agents | 10,000 results/s | 100 ms | ≤ 2× |
| XL | 64 tenants × 300 agents | 25,000 results/s | 200 ms | ≤ 2× |

The inflation ratio applies above a **materiality floor** (5 ms): a 100×
"inflation" of microseconds is scheduler noise, not a noisy neighbor — the
quiet tenant's experience is still excellent. The floor is **the same 5 ms
in CI and at full scale** (U-055; CI briefly carried a 6×-loosened floor —
that divergence is gone, see the scenario design below). **Correctness has
no floor and no scale exemption**: every quiet-tenant result must land
complete and correctly scoped no matter what the neighbor does (guardrail 1
under load).

## The noisy-neighbor scenario

Each measurement is a temporally-adjacent **(solo, noisy) pair** on the
shared pooled path: the quiet tenant alone — baseline p95 — then the same
quiet workload immediately beside a neighbor flooding at 10× volume. The
scenario runs **3 pairs and gates on the median pair** (U-055): host-wide
slowness on a shared CI runner hits both sides of a pair (the ratio
self-normalizes), and a transient stall poisons at most one pair (the
median absorbs it) — which is what lets CI enforce the same documented
floor as reference hardware instead of a loosened one. Sustained contention
inflates every pair and still trips. Reported: the median pair's solo p95,
under-noise p95 and inflation ratio, plus the hard correctness verdict
(AND-ed over every phase of every pair).

## Running it

- **CI (every pass):** `TestScaleGateCI` runs the M tier at 5% scale —
  proving the GATE (profiles drive, SLOs evaluate, isolation holds), not
  the platform. Absolute throughput floors don't apply at CI scale;
  correctness and material inflation do.
- **Full scale (reference hardware):** `make scale-gate TIER=L` (or `XL`)
  sets `PROBECTL_SCALE=1` and runs the real shape with the absolute SLOs
  armed. Record the numbers here when run:

| Date | Tier | Hardware | Throughput | Publish p95 | Inflation | Verdict |
|---|---|---|---|---|---|---|
| _pending_ | L | _reference hardware TBD_ | — | — | — | — |
| _pending_ | XL | _reference hardware TBD_ | — | — | — | — |

The pooled-Postgres side of multi-tenant isolation under load (RLS cost,
per-tenant query p95) remains covered by the S18a `perf-smoke` integration
job (`DrivePooled`); the S-T7 fairness sprint extends it per the plan.

Honesty notes: the in-process harness measures the bus→pipeline→store
path — it excludes network hops, real ClickHouse, and gRPC agent
transport, which the full-stack `test/` soak covers separately. CI-scale
numbers prove the gate's mechanics only; never quote them as platform
capability.
