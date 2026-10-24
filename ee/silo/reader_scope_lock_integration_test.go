// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// overlapScope records how many reader-scope operations on one database run
// at once, across every provisioner sharing it.
type overlapScope struct {
	inside, peak atomic.Int32
}

func (o *overlapScope) hold() {
	n := o.inside.Add(1)
	for {
		p := o.peak.Load()
		if n <= p || o.peak.CompareAndSwap(p, n) {
			break
		}
	}
	time.Sleep(30 * time.Millisecond) // a policy-then-grant (or revoke) sequence in flight
	o.inside.Add(-1)
}

func (o *overlapScope) Endpoint(string) string                       { return "https://ch:8443" }
func (o *overlapScope) Ensure(context.Context, string, string) error { o.hold(); return nil }
func (o *overlapScope) Verify(context.Context, string, string) error { return nil }
func (o *overlapScope) Revoke(context.Context, string, string) error { o.hold(); return nil }

// TestReaderScopeEnsureAndRevokeNeverInterleaveAcrossReplicas (DPR-329): two
// provisioners on separate Postgres sessions, as two replicas are, run one
// tenant's boot catch-up (Ensure) and teardown revoke concurrently. The
// per-database advisory lock lets only one touch the reader scope at a time;
// without it an Ensure's grant could land after a Revoke had dropped the
// policy, leaving a grant with no policy.
func TestReaderScopeEnsureAndRevokeNeverInterleaveAcrossReplicas(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	scope := &overlapScope{}
	replicaA := NewProvisioner(pool, CHPlanes{Readers: []ReaderScope{scope}}, nil, 0, log)
	replicaB := NewProvisioner(pool, CHPlanes{Readers: []ReaderScope{scope}}, nil, 0, log)
	tenant := "6d1f0d6e-0000-4000-8000-00000000d329"
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = replicaA.CatchUpReaderScope(ctx, tenant, "") }()
		go func() { defer wg.Done(); _ = replicaB.teardownCH(ctx, tenant, "") }()
	}
	wg.Wait()
	if peak := scope.peak.Load(); peak != 1 {
		t.Fatalf("%d reader-scope operations on one tenant's database ran at once across replicas, want 1 (DPR-329)", peak)
	}
}
