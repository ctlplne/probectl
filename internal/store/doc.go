// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package store holds probectl's tenant-scoped datastore adapters. S1 introduces
// the PostgreSQL connection pool (store.DB) and the readiness Pinger; the
// migration runner lives in the migrate subpackage. Tenant-scoped repositories
// (Postgres RLS / predicate scoping), ClickHouse, TSDB, graph, and object-store
// adapters land in S2 and beyond (CLAUDE.md §5).
package store
