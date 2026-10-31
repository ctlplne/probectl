// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowsnapshot

import (
	"errors"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A snapshot operation holds the outer writer lease, the cache lease, and a
// short metadata transaction. Bound admission BEFORE acquiring any of those
// connections: otherwise waiting invalidators can exhaust the pool and prevent
// the builder they are draining from publishing. Every service/lifecycle on
// this pool shares this admission budget. It stores no results or key material;
// separate replicas have separate pools and still share the durable PG leases.
// Entries live for their deployment pool's process lifetime.
var poolAdmission sync.Map

func admissionFor(pool *pgxpool.Pool) (chan struct{}, error) {
	if pool == nil || pool.Config().MaxConns < 4 {
		return nil, errors.New("flow snapshots require four database connections: one singleton lease and three working connections")
	}
	capacity := max(1, (int(pool.Config().MaxConns)-1)/3)
	gate, _ := poolAdmission.LoadOrStore(pool, make(chan struct{}, capacity))
	return gate.(chan struct{}), nil
}
