// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

// Shared DB test helpers for the store package. These live under
// `integration || isolation` (not `integration` alone) because the isolation
// gate (`make test-isolation`, -tags=isolation) compiles store tests tagged
// `integration || isolation` — e.g. permissions_disabled_integration_test.go —
// which call setup()/inTenant(). When these helpers were integration-only the
// store package failed to COMPILE under -tags=isolation (undefined: setup /
// inTenant), so the cross-tenant-isolation CI job never even built. Keeping the
// helpers here keeps both build tags green (integration is a subset of the
// constraint, so the integration suite is unaffected).

package store

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func dsn() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl@localhost:5432/postgres?sslmode=disable"
}

func setup(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

func inTenant(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id string, fn func(context.Context, tenancy.Scope) error) {
	t.Helper()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id)), pool, fn); err != nil {
		t.Fatalf("InTenant(%s): %v", id, err)
	}
}
