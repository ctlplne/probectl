// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/inventory"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// TestPostgresViewStorePersistsAndIsolates is the PLAT-06 regression for
// inventory saved views: they were process-memory only. The Postgres-backed
// store must persist them across a restart/replica and isolate them per tenant
// (FORCE RLS) and per owner within a tenant.
func TestPostgresViewStorePersistsAndIsolates(t *testing.T) {
	url := os.Getenv("PROBECTL_DATABASE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_DATABASE_URL not set — inventory saved-view durability gate runs in CI")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	tenants := store.NewTenants(pool)
	tnA, err := tenants.Create(ctx, fmt.Sprintf("invviews-a-%d", time.Now().UnixNano()), "InvViews A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tnB, err := tenants.Create(ctx, fmt.Sprintf("invviews-b-%d", time.Now().UnixNano()), "InvViews B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	s := inventory.NewPostgresViewStore(pool)
	saved, err := s.Save(ctx, tnA.ID, "owner-1", inventory.SaveViewInput{
		Surface: inventory.SurfaceEndpoints, Name: "down endpoints", Filters: map[string]string{"status": "down"},
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	// "Restart" / second replica.
	s2 := inventory.NewPostgresViewStore(pool)
	got, err := s2.Get(ctx, tnA.ID, "owner-1", saved.ID)
	if err != nil {
		t.Fatalf("PLAT-06: saved view did not survive restart: %v", err)
	}
	if got.Name != "down endpoints" || got.Filters["status"] != "down" {
		t.Fatalf("PLAT-06: saved view round-trip mismatch: %+v", got)
	}
	if list, _ := s2.List(ctx, tnA.ID, "owner-1", inventory.SurfaceEndpoints); len(list) != 1 {
		t.Fatalf("PLAT-06: owner-1 should see its 1 saved view, got %d", len(list))
	}

	// Owner isolation within the tenant.
	if list, _ := s2.List(ctx, tnA.ID, "owner-2", ""); len(list) != 0 {
		t.Errorf("owner isolation: owner-2 sees %d of owner-1's views, want 0", len(list))
	}
	if _, err := s2.Get(ctx, tnA.ID, "owner-2", saved.ID); !errors.Is(err, inventory.ErrNotFound) {
		t.Errorf("owner isolation: owner-2 Get another owner's view = %v, want ErrNotFound", err)
	}

	// Tenant isolation (FORCE RLS): tenant B sees nothing of tenant A's.
	if _, err := s2.Get(ctx, tnB.ID, "owner-1", saved.ID); !errors.Is(err, inventory.ErrNotFound) {
		t.Errorf("tenant isolation: tenant B Get tenant A's view = %v, want ErrNotFound", err)
	}
	if list, _ := s2.List(ctx, tnB.ID, "owner-1", ""); len(list) != 0 {
		t.Errorf("tenant isolation: tenant B sees %d of tenant A's views, want 0", len(list))
	}
}
