// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package store holds probectl's tenant-scoped datastore adapters. S1 introduces
// the PostgreSQL connection pool (store.DB) and the readiness Pinger; the
// migration runner lives in the migrate subpackage. Tenant-scoped repositories
// (Postgres RLS / predicate scoping), ClickHouse, TSDB, graph, and object-store
// adapters land in S2 and beyond (docs/repository-layout.md).
package store
