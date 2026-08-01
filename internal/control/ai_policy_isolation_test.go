// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build isolation

package control

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestAuthorEgressPolicyTenantIsolation(t *testing.T) {
	ctx := context.Background()
	dsn := os.Getenv("PROBECTL_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://probectl@localhost:5432/postgres?sslmode=disable"
	}
	db, err := store.Open(ctx, dsn, 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open isolation database: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	t.Cleanup(db.Close)
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	suffix := time.Now().UnixNano()
	tenants := store.NewTenants(db.Pool())
	tenantA, err := tenants.Create(ctx, fmt.Sprintf("ai-policy-a-%d", suffix), "AI Policy A")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tenantB, err := tenants.Create(ctx, fmt.Sprintf("ai-policy-b-%d", suffix), "AI Policy B")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	if err := tenancy.InProvider(ctx, db.Pool(), func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO tenant_governance (tenant_id, ai_remote_egress)
			VALUES ($1, true), ($2, false)
			ON CONFLICT (tenant_id) DO UPDATE
			SET ai_remote_egress = EXCLUDED.ai_remote_egress`,
			tenantA.ID, tenantB.ID)
		return err
	}); err != nil {
		t.Fatalf("seed isolated tenant policies: %v", err)
	}

	policy := tenantEgressPolicy(db.Pool())
	allowedA, err := policy(ctx, tenantA.ID)
	if err != nil || !allowedA {
		t.Fatalf("tenant A policy = (%t, %v), want true", allowedA, err)
	}
	allowedB, err := policy(ctx, tenantB.ID)
	if err != nil || allowedB {
		t.Fatalf("tenant B policy = (%t, %v), want false", allowedB, err)
	}

	// Reverse the two rows and read again. This proves the lookup is bound to the
	// requested tenant at both the transaction/RLS layer and SQL predicate; one
	// tenant's consent can never be reused as process-wide consent.
	if err := tenancy.InProvider(ctx, db.Pool(), func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `
			UPDATE tenant_governance
			SET ai_remote_egress = CASE tenant_id WHEN $1 THEN false WHEN $2 THEN true END
			WHERE tenant_id IN ($1, $2)`,
			tenantA.ID, tenantB.ID)
		return err
	}); err != nil {
		t.Fatalf("reverse isolated tenant policies: %v", err)
	}
	allowedA, err = policy(ctx, tenantA.ID)
	if err != nil || allowedA {
		t.Fatalf("tenant A reversed policy = (%t, %v), want false", allowedA, err)
	}
	allowedB, err = policy(ctx, tenantB.ID)
	if err != nil || !allowedB {
		t.Fatalf("tenant B reversed policy = (%t, %v), want true", allowedB, err)
	}
}
