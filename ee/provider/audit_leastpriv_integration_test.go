// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package provider

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// TestProviderAuditListUnderTheLeastPrivilegeServeLogin: the provider
// console's audit view (GET /provider/v1/audit) pages the provider stream.
// It handed the bare pool to the audit reader, which only worked while the
// serve login was a superuser; under the least-privilege login TEN-01 ships
// (probectl_provider assume-only) every page was "permission denied for table
// provider_audit_events", a 500 in the console.
func TestProviderAuditListUnderTheLeastPrivilegeServeLogin(t *testing.T) {
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres: %v", err)
	}
	defer admin.Close()
	if err := admin.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, admin); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	run := time.Now().UnixNano()
	role := fmt.Sprintf("probectl_rt_provaudit_%d", run)
	const pw = "provaudit-pw"
	for _, stmt := range []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD '` + pw + `' NOSUPERUSER NOBYPASSRLS`,
		`GRANT probectl_app TO ` + role,
		`GRANT probectl_provider TO ` + role + ` WITH INHERIT FALSE, SET TRUE`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	u, err := url.Parse(testsupport.PostgresDSN())
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, pw)
	serve, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		serve.Close()
		_, _ = admin.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})

	stream := &providerAudit{pool: serve}
	action := fmt.Sprintf("leastpriv.audit_%d", run)
	if err := stream.Append(ctx, "root@msp.example", action, "provider", nil); err != nil {
		t.Fatalf("append as the serve login: %v", err)
	}
	for _, newestFirst := range []bool{true, false} {
		events, err := stream.ListAudit(ctx, 0, 50, audit.Filter{Action: action}, newestFirst)
		if err != nil || len(events) != 1 || events[0].Action != action {
			t.Fatalf("the console's audit page (newest first %v) as the serve login = %+v, %v", newestFirst, events, err)
		}
	}
}
