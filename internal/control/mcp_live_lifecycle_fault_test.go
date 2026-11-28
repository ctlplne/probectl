// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestMCPUnreadablePostgresLifecycleRefusesOnlyTheAffectedTenant(t *testing.T) {
	_, db := setupAPIServerWithLatest(t, nil)
	ctx := t.Context()
	tenant := freshTenant(t, db, "mcp-lifecycle-owner")
	sibling := freshTenant(t, db, "mcp-lifecycle-sibling")
	tokens := make(map[string]string, 2)
	for _, tenantID := range []string{tenant, sibling} {
		var userID string
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), db.Pool(), func(ctx context.Context, scope tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, scope, "mcp@"+tenantID+".test", "MCP lifecycle reviewer")
			if err == nil {
				userID = user.ID
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		token, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.NewMCPTokens(db.Pool()).Create(ctx, tenantID, userID, "lifecycle", crypto.Hash([]byte(token))); err != nil {
			t.Fatal(err)
		}
		tokens[tenantID] = token
	}

	// Shadow the registry only on the lifecycle connection. The production
	// query still runs as probectl_provider. The token pool and other tests
	// keep the real registry throughout.
	cfg, err := pgxpool.ParseConfig(integrationDSN())
	if err != nil {
		t.Fatal(err)
	}
	cfg.MinConns, cfg.MaxConns = 0, 1
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if _, err := conn.Exec(ctx, `CREATE TEMP TABLE lifecycle_fault (id uuid PRIMARY KEY, broken boolean NOT NULL)`); err != nil {
			return err
		}
		if _, err := conn.Exec(ctx, `INSERT INTO lifecycle_fault VALUES ($1, true), ($2, false)`, tenant, sibling); err != nil {
			return err
		}
		if _, err := conn.Exec(ctx, `CREATE TEMP VIEW tenants AS
			SELECT t.id, CASE WHEN f.broken THEN current_setting('probectl.dpr440_' || t.id::text) ELSE t.status::text END AS status
			FROM public.tenants t JOIN lifecycle_fault f USING (id)`); err != nil {
			return err
		}
		_, err := conn.Exec(ctx, `GRANT SELECT ON pg_temp.tenants TO `+pgx.Identifier{tenancy.ProviderRole}.Sanitize())
		return err
	}
	statusPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(statusPool.Close)
	if _, err := readTenantStatus(ctx, statusPool, tenant); err == nil {
		t.Fatal("the affected tenant status query unexpectedly succeeded")
	} else {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42704" || !strings.Contains(pgErr.Message, "probectl.dpr440_") {
			t.Fatalf("expected the intentional PostgreSQL status failure, got %v", err)
		}
	}

	authenticator := NewMCPAuthenticator(db.Pool(), NewTenantStatusCache(statusPool, 0), false)
	principal, err := authenticator.Authenticate(ctx, tokens[tenant])
	var unavailable *apierror.Error
	if principal != nil || !errors.As(err, &unavailable) || unavailable.Kind != apierror.KindUnavailable || strings.Contains(err.Error(), "probectl.dpr440_") {
		t.Fatalf("the affected tenant must fail closed without the database diagnostic, principal present: %t, err: %v", principal != nil, err)
	}
	for _, tenantID := range []string{sibling, tenant} {
		if tenantID == tenant {
			if _, err := statusPool.Exec(ctx, `UPDATE lifecycle_fault SET broken = false WHERE id = $1`, tenant); err != nil {
				t.Fatal(err)
			}
		}
		principal, err := authenticator.Authenticate(ctx, tokens[tenantID])
		if err != nil || principal == nil || principal.TenantID != tenantID {
			t.Fatalf("a readable tenant must authenticate as itself, err: %v", err)
		}
	}
}
