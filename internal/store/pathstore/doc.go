// Package pathstore persists discovered network Paths (S10). ClickHouse is the
// durable store for this high-cardinality, time-series path data (CLAUDE.md §4);
// an in-memory store backs the lightweight mode and tests. Every write is
// tenant-scoped — tenant_id is the partition key in ClickHouse — so path data can
// never cross a tenant boundary.
//
// The ClickHouse adapter uses ClickHouse's HTTP interface (no native-driver
// dependency; the same approach as the Prometheus TSDB writer), which keeps the
// build lean and sovereignty-safe and supports TLS via an https URL.
package pathstore
