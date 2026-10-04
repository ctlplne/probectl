// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package cluster

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/cluster/pglease"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PLAT-19: a singleton task carries a lease-epoch guard in its context, so
// every write transaction it opens verifies — FOR SHARE, inside the same
// transaction — that its leadership term is still current. Once a second
// replica has superseded the lease (epoch+1), the first replica's guarded write
// must fail closed with ErrFenced and never reach (let alone commit) its body,
// closing the window the asynchronous Renew check left open.
func TestSingletonEpochGuardFencesSupersededWriter(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	defer pool.Close()

	name := fmt.Sprintf("guard-%d", time.Now().UnixNano())
	lease, err := pglease.New(pool, name, "replica-a")
	if err != nil {
		t.Fatalf("new lease: %v", err)
	}
	token, won, err := lease.Acquire(ctx)
	if err != nil || !won {
		t.Fatalf("acquire: won=%v err=%v", won, err)
	}
	defer func() { _ = lease.Release(context.Background(), token) }()

	// While replica-a keeps running, replica-b takes over: the ledger epoch
	// advances and the holder changes (exactly what pglease.Acquire does).
	if _, err := pool.Exec(ctx,
		`UPDATE cluster_singleton_leases SET epoch = epoch + 1, holder_id = 'replica-b' WHERE lease_name = $1`,
		name); err != nil {
		t.Fatalf("simulate replica-b takeover: %v", err)
	}

	// replica-a's guarded write must fence BEFORE its body runs.
	guardCtx := tenancy.WithTxGuard(ctx, LeaseGuard(token))
	bodyRan := false
	err = tenancy.InProvider(guardCtx, pool, func(ctx context.Context, q tenancy.Querier) error {
		bodyRan = true
		_, e := q.Exec(ctx, `SELECT 1`)
		return e
	})
	if !errors.Is(err, pglease.ErrFenced) {
		t.Fatalf("superseded holder's guarded write must fail with ErrFenced, got %v", err)
	}
	if bodyRan {
		t.Fatal("the write body must not run once the lease epoch is superseded")
	}

	// The CURRENT holder (replica-b's token) passes the guard and runs its body.
	current := pglease.Token{Name: name, HolderID: "replica-b", Epoch: token.Epoch + 1}
	currentRan := false
	if err := tenancy.InProvider(tenancy.WithTxGuard(ctx, LeaseGuard(current)), pool,
		func(_ context.Context, _ tenancy.Querier) error {
			currentRan = true
			return nil
		}); err != nil {
		t.Fatalf("current holder's guarded write must succeed, got %v", err)
	}
	if !currentRan {
		t.Fatal("current holder's write body must run")
	}
}

// PLAT-19: the live cluster_timeline() wrapper (migration 0121) returns the
// real WAL timeline through the least-privilege app role, so the prober can
// read the automatic failover signal.
func TestClusterTimelineWrapperReadableByProber(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	defer pool.Close()

	p := NewPGProber(pool).Probe(ctx)
	if p.Err != nil {
		t.Fatalf("probe: %v", p.Err)
	}
	if p.Timeline <= 0 {
		t.Fatalf("prober must read a positive WAL timeline via cluster_timeline(), got %d", p.Timeline)
	}
}
