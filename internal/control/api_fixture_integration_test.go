// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// Shared verbatim harness: both build tags retain the same database,
// migration, lifecycle and tenant-status setup. No proof is dropped.
func integrationDSN() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable"
}

func setupAPIServerWithLatest(t *testing.T, latest *LatestResults) (*Server, *store.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, integrationDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		db.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(db.Close)
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "dev"}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil).
		WithTenantStatus(NewTenantStatusCache(db.Pool(), 0))
	if latest != nil {
		srv.WithLatestResults(latest)
	}
	return srv, db
}
