// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && !probectl_core

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestOneShotCommandsRouteSiloedTenants (DPR-045): before any DB-backed
// one-shot command runs, dispatchDBCommand installs the tenancy router the
// serving process uses, so a siloed tenant's rows go to its own schema — the
// place the control plane later looks — instead of the pooled public schema.
// The router is observed through the search_path it sets; provisioning the
// schema itself is the provisioner's job and is covered in ee/silo.
func TestOneShotCommandsRouteSiloedTenants(t *testing.T) {
	db := setupBootstrapAdminDB(t)
	pool := db.Pool()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	slug := fmt.Sprintf("dpr045-%d", time.Now().UnixNano())
	var siloed string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (slug, name, isolation_model, residency) VALUES ($1, $1, 'siloed', '') RETURNING id::text`,
		slug).Scan(&siloed); err != nil {
		t.Fatalf("create siloed tenant: %v", err)
	}
	t.Cleanup(func() {
		tenancy.SetRouter(nil)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, siloed)
	})
	searchPath := func(tenantID string) string {
		t.Helper()
		var path string
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SHOW search_path`).Scan(&path)
		})
		if err != nil {
			t.Fatalf("search_path for %s: %v", tenantID, err)
		}
		return path
	}

	// Without the router (the old one-shot behavior) the siloed tenant is
	// served from the pooled schema.
	tenancy.SetRouter(nil)
	if p := searchPath(siloed); strings.Contains(p, "t_") {
		t.Fatalf("precondition: no router yet, but search_path = %q", p)
	}

	// What dispatchDBCommand does before bootstrap-admin, mcp-token, ...:
	if err := attachEETenancyRouter(&config.Config{}, pool, log); err != nil {
		t.Fatalf("attach tenancy router: %v", err)
	}
	if p := searchPath(siloed); !strings.HasPrefix(p, `"t_`) && !strings.HasPrefix(p, "t_") {
		t.Fatalf("siloed tenant must route to its own schema, search_path = %q", p)
	}
	if p := searchPath(tenancy.DefaultTenantID.String()); strings.Contains(p, "t_") {
		t.Fatalf("the pooled default tenant must stay on the public schema, search_path = %q", p)
	}

	// A data-plane config the serving process would reject is rejected here
	// too, before any row is written.
	if err := attachEETenancyRouter(&config.Config{DataPlanes: "broken"}, pool, log); err == nil {
		t.Fatal("a malformed PROBECTL_DATAPLANES must fail the one-shot command")
	}
}
