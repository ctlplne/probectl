// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package pathstore persists discovered network Paths (S10). ClickHouse is the
// durable store for this high-cardinality, time-series path data (docs/architecture.md);
// an in-memory store backs the lightweight mode and tests. Every write is
// tenant-scoped — tenant_id is the partition key in ClickHouse — so path data can
// never cross a tenant boundary.
//
// The ClickHouse adapter uses ClickHouse's HTTP interface (no native-driver
// dependency; the same approach as the Prometheus TSDB writer), which keeps the
// build lean and sovereignty-safe and supports TLS via an https URL.
//
// Duplicate semantics (CORRECT-010). A path save mints a fresh path_id and a
// fresh now() timestamp per call, and the table is a plain MergeTree (no dedup
// key). At-least-once delivery can therefore store the SAME discovery twice as
// two distinct snapshots. This is BENIGN by construction: the only read,
// Latest(), selects the single most-recent snapshot for a target
// (ORDER BY ts DESC LIMIT 1, then reads exactly that path_id's hops/links), so a
// redelivered duplicate is never double-counted or double-rendered — it is at
// most redundant storage that the retention TTL reclaims. Unlike the flow / eBPF
// / OTLP planes (which AGGREGATE across rows and so need ReplacingMergeTree +
// FINAL), the path plane reads a single latest snapshot, so a ReplacingMergeTree
// would add merge cost for no correctness gain. The dedup-harmless contract is
// pinned by TestLatestReturnsOneSnapshotAfterResave.
package pathstore
