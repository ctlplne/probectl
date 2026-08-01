// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package cluster

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// The S-EE2 integration leg (live Postgres): the PGProber reads the REAL
// pg_is_in_recovery() and the replicated cluster_state row, and cluster_promote
// bumps the epoch — so the Manager fences a (simulated) stale epoch exactly as
// the unit suite does, but against the actual schema + function.
func itPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.PostgresDSN()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func TestPGProberAndPromotePG(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()

	// The primary is not in recovery; the prober reads its epoch + region.
	p := NewPGProber(pool)
	before := p.Probe(ctx)
	if before.Err != nil {
		t.Fatalf("probe: %v", before.Err)
	}
	if before.InRecovery {
		t.Skip("test database is a replica (in recovery) — promotion test needs a primary")
	}

	// A promotion bumps the epoch monotonically and records the region.
	var newEpoch int64
	if err := pool.QueryRow(ctx, `SELECT cluster_promote($1, $2)`, "us-east", "it-test").Scan(&newEpoch); err != nil {
		t.Fatalf("cluster_promote: %v", err)
	}
	if newEpoch != before.Epoch+1 {
		t.Fatalf("promote must bump the epoch by 1: %d -> %d", before.Epoch, newEpoch)
	}
	after := p.Probe(ctx)
	if after.Epoch != newEpoch || after.WriterRegion != "us-east" {
		t.Fatalf("prober must read the promoted epoch/region: %+v", after)
	}

	// The Manager treats the real primary as usable; a simulated stale probe
	// (a lower epoch than the high-water mark just observed) is fenced.
	m := NewManager(Topology{Region: "us-east"}, p, nil)
	m.Refresh(ctx)
	if ok, reason := m.WriterUsable(); !ok {
		t.Fatalf("the real primary must be usable: %s", reason)
	}
	stale := &fakeProbe{p: Probe{InRecovery: false, Epoch: newEpoch - 1, WriterRegion: "old"}}
	m2 := NewManager(Topology{Region: "us-east"}, stale, p) // reader=real primary sets the high-water
	m2.Refresh(ctx)
	if ok, _ := m2.WriterUsable(); ok {
		t.Fatal("a writer on a lower epoch than the replica's must be fenced (split-brain)")
	}
}
