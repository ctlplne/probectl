// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package perf is probectl's reusable load/perf harness (S18a, perf-foundation).
//
// It drives the core path — agents → bus → stores → query — at a defined
// synthetic scale and captures baseline numbers (ingest throughput, query
// p50/p95) plus a pooled multi-tenant smoke that asserts tenant-scoped queries
// stay correct AND bounded under mixed-tenant load. The point is a cheap,
// repeatable early-warning baseline checked in at GA (M6): a regression guard,
// not a soak test. The full L/XL/XXL scale gate (S48) and the per-tenant fairness
// gate (S-T7) reuse and extend these drivers.
//
// Two drivers, both pure (no global state):
//
//   - DriveIngest publishes probe results through the lightweight bus → pipeline
//     consumer → TSDB path and measures end-to-end throughput + publish latency.
//   - DrivePooled runs tenant-scoped queries concurrently across many tenants
//     sharing the pooled Postgres stores, measuring query latency AND asserting
//     isolation (every query sees exactly its tenant's rows — a cross-tenant
//     leak or a scoping bug shows up as a wrong count). This is where a pooled
//     cardinality or RLS-cost problem surfaces first (CLAUDE.md §7 guardrail 1).
//
// Baseline holds the floors/ceilings the smoke asserts against; the recorded GA
// numbers and run instructions live in docs/perf-baseline.md. The smoke tests
// are the harness's own use: internal/perf/perf_test.go (no DB, always runs) and
// internal/perf/pooled_integration_test.go (the `integration` build tag, against
// the Postgres service).
//
// Placement note: the harness lives here (a reusable main-module library) rather
// than the black-box test/ module, matching how every other integration test in
// this repo is structured (in-module, `integration`-tagged, reaching Postgres via
// PROBECTL_DATABASE_URL). The test/ module stays reserved for full-stack soak.
package perf
