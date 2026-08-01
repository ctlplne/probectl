// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/topology"
	"github.com/ctlplne/probectl/migrations"
)

// TestTopologyEraseWriteFenceTwoTenant proves the real runtime topology store
// refuses tenant-A mutations after the durable erasure fence while tenant B
// remains writable.
func TestTopologyEraseWriteFenceTwoTenant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	db, err := store.Open(ctx, testsupport.PostgresDSN(), 4, 0, time.Second)
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	testsupport.LockPostgresPublicCatalog(t, db.Pool())

	stamp := time.Now().UTC().UnixNano()
	tenantA := insertTopologyFenceTenant(ctx, t, db, fmt.Sprintf("topology-fence-a-%d", stamp))
	tenantB := insertTopologyFenceTenant(ctx, t, db, fmt.Sprintf("topology-fence-b-%d", stamp))
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
	})

	rt := newServeRuntime(
		&config.Config{TopologyEngine: "memory"},
		db,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&serveStores{},
		nil,
	)
	t.Cleanup(rt.stop)
	if err := rt.buildServeEngines(); err != nil {
		t.Fatalf("build serve engines: %v", err)
	}
	if !topology.HasTenantWriteFence(rt.topoStore) {
		t.Fatal("production serve runtime exposed an unfenced topology Store")
	}
	if _, ok := rt.topoStore.(interface{ DeleteTenant(string) int }); !ok {
		t.Fatal("topology fence hid the lifecycle erasure capability")
	}
	if _, ok := rt.topoStore.(interface {
		PruneTenantBefore(string, time.Time) int
	}); !ok {
		t.Fatal("topology fence hid the lifecycle retention capability")
	}
	a, err := rt.topoStore.ForTenant(tenantA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := rt.topoStore.ForTenant(tenantB)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	a.ObserveServiceEdge(topology.ServiceEdgeInput{Source: "a-before", Destination: "a-db"}, at)
	b.ObserveServiceEdge(topology.ServiceEdgeInput{Source: "b-before", Destination: "b-db"}, at)

	if err := commitTopologyEraseFence(ctx, db, tenantA); err != nil {
		t.Fatalf("commit tenant-A erasure fence: %v", err)
	}
	a.ObserveServiceEdge(topology.ServiceEdgeInput{Source: "a-after", Destination: "a-forbidden"}, at.Add(time.Second))
	b.ObserveServiceEdge(topology.ServiceEdgeInput{Source: "b-after", Destination: "b-allowed"}, at.Add(time.Second))

	if got := len(a.Latest().Nodes); got != 2 {
		t.Fatalf("tenant A topology mutated after erasure fence: nodes=%d, want 2", got)
	}
	if got := len(b.Latest().Nodes); got != 4 {
		t.Fatalf("tenant B topology was blocked by tenant A fence: nodes=%d, want 4", got)
	}
}

func commitTopologyEraseFence(ctx context.Context, db *store.DB, tenantID string) error {
	return tenancy.InProvider(ctx, db.Pool(), func(ctx context.Context, q tenancy.Querier) error {
		if err := tenancy.LockTenantWrites(ctx, q, tenantID); err != nil {
			return err
		}
		tag, err := q.Exec(
			ctx,
			`UPDATE public.tenants
			    SET status = 'offboarding',
			        audit_write_fenced_at = now(),
			        updated_at = now()
			  WHERE id = $1::uuid
			    AND status = 'active'
			    AND audit_write_fenced_at IS NULL`,
			tenantID,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("tenant was not eligible for topology fence")
		}
		return nil
	})
}

func insertTopologyFenceTenant(ctx context.Context, t *testing.T, db *store.DB, slug string) string {
	t.Helper()
	var tenantID string
	if err := db.Pool().QueryRow(
		ctx,
		`INSERT INTO public.tenants (slug, name)
		 VALUES ($1, $1)
		 RETURNING id::text`,
		slug,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant %q: %v", slug, err)
	}
	return tenantID
}
