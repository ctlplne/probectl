// Package store holds netctl's tenant-scoped datastore adapters. S1 introduces
// the PostgreSQL connection pool (store.DB) and the readiness Pinger; the
// migration runner lives in the migrate subpackage. Tenant-scoped repositories
// (Postgres RLS / predicate scoping), ClickHouse, TSDB, graph, and object-store
// adapters land in S2 and beyond (CLAUDE.md §5).
package store
