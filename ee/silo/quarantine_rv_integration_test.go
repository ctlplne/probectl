// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
)

type hostPlane struct{ ok bool }

func (p hostPlane) ValidResidency(string) bool                             { return p.ok }
func (hostPlane) CatchUp(context.Context, string) error                    { return nil }
func (hostPlane) CatchUpSchema(context.Context, string) error              { return nil }
func (hostPlane) CatchUpReaderScope(context.Context, string, string) error { return nil }
func (hostPlane) MissingSiloTables(context.Context, []string) (map[string][]string, error) {
	return nil, nil
}

// DPR-386 (the reviewer's RV-1 probe): two LIVE processes on one host never
// share an identity, so the healthy one never takes over — and releases —
// the quarantine its sibling holds, and the one-shot view keeps seeing it.
// A process on the host that STOPPED (idle past one interval) is taken over.
func TestSameHostProcessesNeverReleaseEachOthersQuarantine(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	x := mkTenant(t, pool, "d62-host-"+stamp, "hybrid", "mars-"+stamp)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, x) })
	host := "same-host-" + stamp
	mk := func(nonce string, ok bool) (*QuarantineSupervisor, *tenancy.Quarantine) {
		q := tenancy.NewQuarantine()
		s := NewQuarantineSupervisor(QuarantineConfig{Pool: pool, Checks: hostPlane{ok: ok}, Registry: q, Interval: 5 * time.Second,
			Replica: host + "/" + nonce, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
		s.list = func(context.Context) ([]IsolatedTenant, error) {
			return []IsolatedTenant{{ID: x, Model: "hybrid", Status: "active", Residency: "mars-" + stamp}}, nil
		}
		s.tenant = func(context.Context, tenantNotice) error { return nil }
		return s, q
	}
	a, qa := mk("a", false) // cannot see the plane: quarantines X
	b, _ := mk("b", true)   // can: X is healthy here
	if _, err := a.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	events := func(action string) int {
		return count(t, pool, `SELECT count(*) FROM provider_audit_events WHERE target = $1 AND action = $2`, x, action)
	}
	for i := 0; i < 3; i++ {
		a.flush(ctx)
		b.flush(ctx)
		view := tenancy.NewQuarantine()
		if _, err := LoadReplicaQuarantine(ctx, pool, view, time.Minute); err != nil {
			t.Fatal(err)
		}
		if qa.Check(x) == nil || view.Check(x) == nil {
			t.Fatalf("round %d: A refuses X=%v, one-shot view refuses X=%v; both must while A holds it", i, qa.Check(x) != nil, view.Check(x) != nil)
		}
	}
	if events(AuditTenantQuarantined) != 1 || events(AuditTenantReleased) != 0 {
		t.Fatalf("entered=%d released=%d while A still holds X; want 1/0", events(AuditTenantQuarantined), events(AuditTenantReleased))
	}

	// A stops (its row goes idle); a successor on the host takes it over and,
	// as the last holder going, records the release.
	if _, err := pool.Exec(ctx, `UPDATE tenant_quarantine SET checked_at = now() - interval '1 minute' WHERE tenant = $1::uuid AND replica = $2`, x, host+"/a"); err != nil {
		t.Fatal(err)
	}
	c, _ := mk("c", true)
	if _, err := c.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	c.flush(ctx)
	if n := count(t, pool, `SELECT count(*) FROM tenant_quarantine WHERE tenant = $1::uuid`, x); n != 0 || events(AuditTenantReleased) != 1 {
		t.Fatalf("after the takeover: %d rows, %d released events; want 0 and 1", n, events(AuditTenantReleased))
	}
}

// DPR-388 (RV-3): the tenant's own chain carries no replica (host/pod) name;
// the provider stream does.
func TestTenantChainCarriesNoReplicaName(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	x := mkTenant(t, pool, "d62-noreplica-"+stamp, "hybrid", "mars-"+stamp)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, x) })
	prevRouter := tenancy.CurrentRouter()
	t.Cleanup(func() { tenancy.SetRouter(prevRouter) })
	tenancy.SetRouter(NewRouter(pool, nil, 0).WithQuarantine(tenancy.NewQuarantine()))
	s := NewQuarantineSupervisor(QuarantineConfig{Pool: pool, Checks: hostPlane{}, Registry: tenancy.NewQuarantine(),
		Interval: 5 * time.Second, Replica: "ctl01.internal.msp.example/" + stamp, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	s.list = func(context.Context) ([]IsolatedTenant, error) {
		return []IsolatedTenant{{ID: x, Model: "hybrid", Status: "active", Residency: "mars-" + stamp}}, nil
	}
	if _, err := s.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	s.flush(ctx)
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid AND action = $2`, x, AuditTenantQuarantined); n != 1 {
		t.Fatalf("tenant-chain entered events = %d, want 1", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid AND (data ? 'replica' OR data::text LIKE '%ctl01%')`, x); n != 0 {
		t.Fatalf("%d tenant-chain events carry a replica/host name", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM provider_audit_events WHERE target = $1 AND data->>'replica' = $2`, x, s.Replica()); n != 1 {
		t.Fatal("the provider stream lost the replica identity")
	}
}

// DPR-387 (D-71, the reviewer's RV-2 probe): an OFFBOARDING siloed tenant
// whose silo lags a migration (a newer tenant-owned table) is caught up
// schema-only, so its export and verifiable erasure keep working — in
// quarantine mode through the supervisor (stop mode through siloCatchUpAll,
// cmd/probectl-control) — and no row is changed by the catch-up.
func TestOffboardingSiloLaggingAMigrationCanBeExportedAndErased(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	testsupport.LockPostgresPublicCatalog(t, pool)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	slug := "d62-off-" + stamp
	x := mkTenant(t, pool, slug, "siloed", "")
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := prov.Provision(ctx, x, "", tenancy.IsolationSiloed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = prov.Teardown(context.Background(), x, "", tenancy.IsolationSiloed)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, x)
	})
	q := tenancy.NewQuarantine()
	prevRouter, prevQ := tenancy.CurrentRouter(), tenancy.CurrentQuarantine()
	t.Cleanup(func() {
		tenancy.SetRouter(prevRouter)
		tenancy.SetQuarantine(prevQ)
		tenancy.SetSiloRequiredTables(nil)
	})
	tenancy.SetQuarantine(q)
	tenancy.SetRouter(NewRouter(pool, nil, 0).WithQuarantine(q))
	required, err := RequiredSiloTables(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	tenancy.SetSiloRequiredTables(required)
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(x)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO tests (tenant_id, name, type, target, interval_seconds, timeout_seconds, params, enabled)
			 VALUES ($1, 'kept', 'icmp', '192.0.2.1', 60, 5, '{}'::jsonb, true)`, x)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tenants SET status = 'offboarding' WHERE id = $1::uuid`, x); err != nil {
		t.Fatal(err)
	}
	// "A newer migration added a tenant-owned table": the silo lacks it.
	if _, err := pool.Exec(ctx, `DROP TABLE `+pgx.Identifier{SchemaName(x), "device_traps"}.Sanitize()); err != nil {
		t.Fatal(err)
	}

	s := NewQuarantineSupervisor(QuarantineConfig{Pool: pool, Checks: prov, Registry: q, Interval: 5 * time.Second,
		Replica: "d62-off/" + stamp, Log: log})
	s.list = func(context.Context) ([]IsolatedTenant, error) {
		return []IsolatedTenant{{ID: x, Model: "siloed", Status: "offboarding"}}, nil
	}
	if held, err := s.Boot(ctx); err != nil || len(held) != 0 {
		t.Fatalf("Boot of the lagging offboarding silo = %+v %v; want it caught up schema-only, not quarantined", held, err)
	}
	if n := count(t, pool, `SELECT count(*) FROM `+pgx.Identifier{SchemaName(x), "tests"}.Sanitize()+` WHERE name = 'kept'`); n != 1 {
		t.Fatalf("the schema-only catch-up changed data: %d kept rows", n)
	}
	providerAudit := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	life := tenantlife.New(pool, nil, nil, nil, providerAudit, "test backups", log).
		WithIRAttributionLifecycle(postgresWriteFenceIRLifecycle{})
	var bundle bytes.Buffer
	if _, err := life.Export(ctx, x, &bundle); err != nil {
		t.Fatalf("export of the offboarding tenant: %v", err)
	}
	att, err := life.Erase(ctx, x, slug, "privacy-admin")
	if err != nil || !att.Complete {
		t.Fatalf("erasure of the offboarding tenant = %+v, %v", att.Complete, err)
	}
}

// DPR-401 (D-73): a long multi-statement siloed transaction (export,
// erasure, maintenance) holds ACCESS SHARE on its silo's tables from the
// start, so a DROP TABLE committed by another session while it runs blocks,
// and the transaction's LATER statements can never resolve to the pooled
// public table.
func TestDropDuringALongSiloTransactionCannotReachPublic(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	testsupport.LockPostgresPublicCatalog(t, pool)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	x := mkTenant(t, pool, "d62-long-"+stamp, "siloed", "")
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := prov.Provision(ctx, x, "", tenancy.IsolationSiloed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = prov.Teardown(context.Background(), x, "", tenancy.IsolationSiloed)
		_, _ = pool.Exec(context.Background(), `DELETE FROM public.tests WHERE tenant_id = $1::uuid`, x)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, x)
	})
	prevRouter := tenancy.CurrentRouter()
	t.Cleanup(func() { tenancy.SetRouter(prevRouter); tenancy.SetSiloRequiredTables(nil) })
	tenancy.SetRouter(NewRouter(pool, nil, 0).WithQuarantine(tenancy.NewQuarantine()))
	required, err := RequiredSiloTables(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	tenancy.SetSiloRequiredTables(required)

	var dropErr error
	lctx := tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(x)))
	err = tenancy.InTenant(lctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		// The transaction works through other tables first (an export walks
		// them in order); it has not touched tests yet, so only the silo
		// lock taken at its start protects that table.
		var n int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM alert_rules`).Scan(&n); err != nil {
			return err
		}
		// Another session (the migration login) drops tests mid-transaction.
		conn, err := pool.Acquire(context.Background())
		if err != nil {
			return err
		}
		defer conn.Release()
		if _, err := conn.Exec(context.Background(), `SET lock_timeout = '1s'`); err != nil {
			return err
		}
		_, dropErr = conn.Exec(context.Background(), `DROP TABLE `+pgx.Identifier{SchemaName(x), "tests"}.Sanitize()+` CASCADE`)
		_, err = sc.Q.Exec(ctx, `INSERT INTO tests (tenant_id, name, type, target, interval_seconds, timeout_seconds, params, enabled)
			 VALUES ($1, 'late', 'icmp', '192.0.2.1', 60, 5, '{}'::jsonb, true)`, x)
		return err
	})
	if err != nil {
		t.Fatalf("the long transaction failed: %v", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM public.tests WHERE tenant_id = $1::uuid`, x); n != 0 {
		t.Fatalf("%d of the siloed tenant's rows landed in the pooled public.tests", n)
	}
	if dropErr == nil {
		t.Fatal("DROP TABLE succeeded while a long siloed transaction was running; it must block on the transaction's ACCESS SHARE lock")
	}
	if n := count(t, pool, `SELECT count(*) FROM `+pgx.Identifier{SchemaName(x), "tests"}.Sanitize()+` WHERE name = 'late'`); n != 1 {
		t.Fatalf("the later statement's row is not in the silo (%d)", n)
	}
	// The real export takes the same locks and still works.
	var bundle bytes.Buffer
	if _, err := tenantlife.New(pool, nil, nil, nil, nil, "", log).Export(ctx, x, &bundle); err != nil {
		t.Fatalf("export under the silo locks: %v", err)
	}
}
