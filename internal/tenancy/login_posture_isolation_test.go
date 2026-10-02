// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package tenancy_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestAssertLoginRolePosture is the TEN-01 regression. The control plane
// connected to Postgres as a SUPERUSER (rolsuper/rolbypassrls), so RLS was
// bypassed on every bare-pool path. AssertLoginRolePosture now refuses to serve
// as a superuser/BYPASSRLS LOGIN role (fail closed unless the dangerous
// sandbox ack is set), and a least-privilege login (member of probectl_app)
// both passes the check and has RLS actually bite on a bare pool.
func TestAssertLoginRolePosture(t *testing.T) {
	ctx := context.Background()
	su := setup(ctx, t) // the default CI/closure login (probectl) is a superuser
	defer su.Close()

	// A superuser / BYPASSRLS login must be refused, and the dangerous ack must
	// override (non-production sandbox).
	if err := tenancy.AssertLoginRolePosture(ctx, su, false); err == nil {
		t.Fatal("TEN-01: a superuser/BYPASSRLS login role must be refused (boot fails closed)")
	}
	if err := tenancy.AssertLoginRolePosture(ctx, su, true); err != nil {
		t.Errorf("TEN-01: the dangerous ack must allow a superuser login, got %v", err)
	}

	// Provision a least-privilege LOGIN role that is a member of probectl_app.
	const role = "probectl_runtime_ten01_test"
	const pw = "ten01pw"
	_, _ = su.Exec(ctx, `DROP ROLE IF EXISTS `+role)
	if _, err := su.Exec(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD '`+pw+`' NOSUPERUSER NOBYPASSRLS IN ROLE probectl_app`); err != nil {
		t.Fatalf("create least-privilege login: %v", err)
	}
	defer func() { _, _ = su.Exec(context.Background(), `DROP ROLE IF EXISTS `+role) }()

	u, err := url.Parse(dsn())
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.User = url.UserPassword(role, pw)
	lp, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatalf("connect as least-privilege login: %v", err)
	}
	defer lp.Close()

	// The least-privilege login passes the posture check...
	if err := tenancy.AssertLoginRolePosture(ctx, lp, false); err != nil {
		t.Fatalf("TEN-01: a NOSUPERUSER NOBYPASSRLS login must pass the posture check: %v", err)
	}
	// ...and RLS bites on the bare pool: a predicate-free read with no tenant set
	// returns zero rows (the full-table escalation path the superuser login had).
	var n int
	if err := lp.QueryRow(ctx, `SELECT count(*) FROM tests`).Scan(&n); err != nil {
		t.Fatalf("TEN-01: bare predicate-free SELECT on tests as the serve login: %v", err)
	}
	if n != 0 {
		t.Errorf("TEN-01: a predicate-free read on the raw serve pool must return 0 rows (RLS enforced), got %d", n)
	}
}
