// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func setupBootstrapAdminDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, testsupport.PostgresDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open db: %v", err)
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
	return db
}

// DPR-013: the first explicit role grant on a fresh deployment. A person who
// has never logged in gets a user row plus the admin binding; a person who
// already exists keeps their row; re-running is idempotent; the grant is
// audited in the tenant stream; a bogus role or tenant is refused.
func TestBootstrapAdminGrantsFirstAdminIdempotentlyAndAudits(t *testing.T) {
	db := setupBootstrapAdminDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tenant := tenancy.DefaultTenantID.String()
	email := "first-admin-" + strings.ToLower(t.Name()[len("TestBootstrapAdmin"):len("TestBootstrapAdmin")+6]) + "@example.test"

	if err := bootstrapAdmin(ctx, db, log, tenant, " "+strings.ToUpper(email)+" ", "admin", "First Admin"); err != nil {
		t.Fatalf("first grant: %v", err)
	}
	if err := bootstrapAdmin(ctx, db, log, tenant, email, "admin", ""); err != nil {
		t.Fatalf("second grant must be idempotent: %v", err)
	}

	var (
		bindings int
		userID   string
		auditN   int
	)
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.DefaultTenantID), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		u, err := store.Users{}.GetByEmail(ctx, sc, email)
		if err != nil {
			return err
		}
		userID = u.ID
		role, err := store.Roles{}.GetBySlug(ctx, sc, "admin")
		if err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx,
			`SELECT count(*) FROM role_bindings WHERE subject_type = 'user' AND subject_id = $1 AND role_id = $2`,
			u.ID, role.ID).Scan(&bindings); err != nil {
			return err
		}
		return sc.Q.QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE action = 'rbac.bind' AND target = $1 AND actor = $2`,
			u.ID, bootstrapAdminActor).Scan(&auditN)
	})
	if err != nil {
		t.Fatal(err)
	}
	if bindings != 1 {
		t.Fatalf("want exactly one admin binding for %s, got %d", email, bindings)
	}
	if auditN < 1 {
		t.Fatalf("the grant must be audited as rbac.bind by %s (got %d rows)", bootstrapAdminActor, auditN)
	}
	if userID == "" {
		t.Fatal("user row missing after the grant")
	}

	if err := bootstrapAdmin(ctx, db, log, tenant, email, "no-such-role", ""); err == nil || !strings.Contains(err.Error(), "seeded roles are admin, editor, viewer") {
		t.Fatalf("unknown role must be refused with guidance, got %v", err)
	}
	if err := bootstrapAdmin(ctx, db, log, "not-a-uuid", email, "admin", ""); err == nil {
		t.Fatal("a malformed tenant must be refused")
	}
	if err := bootstrapAdmin(ctx, db, log, tenant, "no-at-sign", "admin", ""); err == nil {
		t.Fatal("a malformed email must be refused")
	}
}
