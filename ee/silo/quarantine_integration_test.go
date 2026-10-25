// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// D-62 on real Postgres: the supervisor's quarantine is enforced by the
// registry-backed router and InTenant, audited on the provider stream and on
// the tenant's own chain, mirrored into tenant_quarantine (which a one-shot
// process loads back), and lifted — with both receipts — once the check
// passes. The posture self-check accepts the new provider-domain table.
func TestQuarantineSupervisorOnRealPostgres(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	bad := mkTenant(t, pool, "d62-bad-"+stamp, "hybrid", "mars-"+stamp)
	good := mkTenant(t, pool, "d62-good-"+stamp, "hybrid", "")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = ANY($1::uuid[])`, []string{bad, good})
	})
	if err := tenancy.AssertIsolationPosture(ctx, pool); err != nil {
		t.Fatalf("posture with tenant_quarantine: %v", err)
	}

	q := tenancy.NewQuarantine()
	prevRouter, prevQ := tenancy.CurrentRouter(), tenancy.CurrentQuarantine()
	t.Cleanup(func() { tenancy.SetRouter(prevRouter); tenancy.SetQuarantine(prevQ) })
	tenancy.SetQuarantine(q)
	router := NewRouter(pool, nil, 0).WithQuarantine(q)
	tenancy.SetRouter(router)

	restored := false
	checks := &planeCheck{valid: func(name string) bool { return name == "" || restored }}
	s := NewQuarantineSupervisor(QuarantineConfig{Pool: pool, Checks: checks, Registry: q, Interval: 5 * time.Second,
		Planes: []string{"eu"}, Replica: "d62-real-" + stamp, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	s.list = func(ctx context.Context) ([]IsolatedTenant, error) {
		all, err := s.listIsolated(ctx)
		var mine []IsolatedTenant
		for _, it := range all {
			if it.ID == bad || it.ID == good {
				mine = append(mine, it)
			}
		}
		return mine, err
	}

	held, err := s.Boot(ctx)
	if err != nil || len(held) != 1 || held[0].TenantID != bad || held[0].Reason != tenancy.QuarantinePlaneMissing {
		t.Fatalf("Boot = %+v, %v; want only %s quarantined for its missing plane", held, err, bad)
	}
	if _, err := router.TargetsFor(ctx, bad); !errors.Is(err, tenancy.ErrTenantQuarantined) {
		t.Fatalf("router served the quarantined tenant: %v", err)
	}
	if _, err := router.TargetsFor(ctx, good); err != nil {
		t.Fatalf("router refused the healthy tenant: %v", err)
	}
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(bad)), pool, func(context.Context, tenancy.Scope) error { return nil })
	if !errors.Is(err, tenancy.ErrTenantQuarantined) {
		t.Fatalf("InTenant for the quarantined tenant = %v", err)
	}

	s.flush(ctx)
	if n := count(t, pool, `SELECT count(*) FROM tenant_quarantine WHERE tenant = $1::uuid AND replica = $2 AND reason = 'residency_plane_missing'`, bad, s.Replica()); n != 1 {
		t.Fatalf("tenant_quarantine rows for the quarantined tenant = %d, want 1", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM provider_audit_events WHERE action = $1 AND target = $2`, AuditTenantQuarantined, bad); n != 1 {
		t.Fatalf("provider stream entered events = %d, want 1", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid AND action = $2 AND actor = $3 AND NOT (data ? 'detail')`, bad, AuditTenantQuarantined, QuarantineActor); n != 1 {
		t.Fatalf("tenant-chain entered events (without the operator detail) = %d, want 1", n)
	}

	oneShot := tenancy.NewQuarantine()
	if n, err := LoadReplicaQuarantine(ctx, pool, oneShot, time.Minute); err != nil || n < 1 || oneShot.Check(bad) == nil || oneShot.Check(good) != nil {
		t.Fatalf("LoadReplicaQuarantine = %d, %v; want the replica's quarantine of %s loaded", n, err, bad)
	}

	restored = true
	s.Recheck(ctx)
	if err := q.Check(bad); err != nil {
		t.Fatalf("the tenant stayed quarantined after its plane returned: %v", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM tenant_quarantine WHERE tenant = $1::uuid`, bad); n != 0 {
		t.Fatalf("tenant_quarantine still holds %d rows after release", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM provider_audit_events WHERE action = $1 AND target = $2`, AuditTenantReleased, bad); n != 1 {
		t.Fatalf("provider stream released events = %d, want 1", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid AND action = $2`, bad, AuditTenantReleased); n != 1 {
		t.Fatalf("tenant-chain released events = %d, want 1", n)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(bad)), pool, func(context.Context, tenancy.Scope) error { return nil }); err != nil {
		t.Fatalf("InTenant after release: %v", err)
	}
}

type planeCheck struct{ valid func(string) bool }

func (p *planeCheck) ValidResidency(name string) bool                        { return p.valid(name) }
func (*planeCheck) CatchUp(context.Context, string) error                    { return nil }
func (*planeCheck) CatchUpReaderScope(context.Context, string, string) error { return nil }
func (*planeCheck) MissingSiloTables(context.Context, []string) (map[string][]string, error) {
	return nil, nil
}

func count(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// DPR-368 (the reviewer's ADV4-1 probe): a siloed tenant whose silo schema is
// missing fails its catch-up and is quarantined; its tenant-chain receipt must
// never fall through to the POOLED public tables. Generally, InTenant refuses
// any siloed tenant whose routed schema does not exist.
func TestMissingSiloSchemaNeverFallsThroughToPublic(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	x := mkTenant(t, pool, "d62-nosilo-"+stamp, "siloed", "")
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, x) })
	if n := count(t, pool, `SELECT count(*) FROM pg_namespace WHERE nspname = $1`, SchemaName(x)); n != 0 {
		t.Fatalf("precondition: silo schema %s exists", SchemaName(x))
	}
	q := tenancy.NewQuarantine()
	prevRouter, prevQ := tenancy.CurrentRouter(), tenancy.CurrentQuarantine()
	t.Cleanup(func() { tenancy.SetRouter(prevRouter); tenancy.SetQuarantine(prevQ) })
	tenancy.SetQuarantine(q)
	tenancy.SetRouter(NewRouter(pool, nil, 0).WithQuarantine(q))

	// The general rule, before any quarantine: an absent silo is refused.
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(x)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO tests (tenant_id, name, type, target) VALUES ($1, 'x', 'ping', 'example.com')`, x)
		return err
	})
	if !errors.Is(err, tenancy.ErrSiloSchemaMissing) {
		t.Fatalf("InTenant for a siloed tenant with no schema = %v, want ErrSiloSchemaMissing", err)
	}

	s := NewQuarantineSupervisor(QuarantineConfig{Pool: pool, Checks: missingSilo{}, Registry: q, Interval: 5 * time.Second,
		Replica: "d62-it-" + stamp, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	s.list = func(context.Context) ([]IsolatedTenant, error) {
		return []IsolatedTenant{{ID: x, Model: "siloed", Status: "active"}}, nil
	}
	held, err := s.Boot(ctx)
	if err != nil || len(held) != 1 || held[0].Reason != tenancy.QuarantineSchemaCatchUpFailed {
		t.Fatalf("Boot = %+v %v", held, err)
	}
	s.flush(ctx)
	for _, table := range []string{"public.audit_events", "public.tests"} {
		if n := count(t, pool, `SELECT count(*) FROM `+table+` WHERE tenant_id = $1::uuid`, x); n != 0 {
			t.Fatalf("%d rows of the SILOED tenant landed in the pooled %s", n, table)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM provider_audit_events WHERE target = $1 AND action = $2`, x, AuditQuarantineNoticeProviderOnly); n != 1 {
		t.Fatalf("provider-only receipts = %d, want the tenant-chain receipt recorded on the provider stream once", n)
	}
	s.mu.Lock()
	pending := len(s.notices)
	s.mu.Unlock()
	if pending != 0 {
		t.Fatalf("%d receipts still pending; a receipt with no chain must not be retried forever", pending)
	}
}

type missingSilo struct{}

func (missingSilo) ValidResidency(string) bool { return true }
func (missingSilo) CatchUp(context.Context, string) error {
	return errors.New(`ERROR: schema "t_x" does not exist (SQLSTATE 3F000)`)
}
func (missingSilo) CatchUpReaderScope(context.Context, string, string) error { return nil }
func (missingSilo) MissingSiloTables(context.Context, []string) (map[string][]string, error) {
	return nil, nil
}

// DPR-381 on real Postgres: two replicas and a restart of one record ONE
// entered event on each stream; the released event comes once, from the last
// holder, and names the replica.
func TestQuarantineTransitionsAreDedupedAcrossReplicasOnRealPostgres(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	x := mkTenant(t, pool, "d62-dedupe-"+stamp, "hybrid", "mars-"+stamp)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, x) })
	prevRouter, prevQ := tenancy.CurrentRouter(), tenancy.CurrentQuarantine()
	t.Cleanup(func() { tenancy.SetRouter(prevRouter); tenancy.SetQuarantine(prevQ) })
	tenancy.SetRouter(NewRouter(pool, nil, 0).WithQuarantine(tenancy.NewQuarantine()))

	restored := false
	checks := &planeCheck{valid: func(name string) bool { return name == "" || restored }}
	start := func(replica string) *QuarantineSupervisor {
		s := NewQuarantineSupervisor(QuarantineConfig{Pool: pool, Checks: checks, Registry: tenancy.NewQuarantine(),
			Interval: 5 * time.Second, Replica: replica, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
		s.list = func(context.Context) ([]IsolatedTenant, error) {
			return []IsolatedTenant{{ID: x, Model: "hybrid", Status: "active", Residency: "mars-" + stamp}}, nil
		}
		if _, err := s.Boot(ctx); err != nil {
			t.Fatal(err)
		}
		s.flush(ctx)
		return s
	}
	r1, r2 := "d62-a-"+stamp, "d62-b-"+stamp
	start(r1)
	s2 := start(r2)
	s1 := start(r1) // replica-1 restarts with the same identity
	events := func(action string) int {
		return count(t, pool, `SELECT count(*) FROM provider_audit_events WHERE action = $1 AND target = $2`, action, x)
	}
	chain := func(action string) int {
		return count(t, pool, `SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid AND action = $2`, x, action)
	}
	if events(AuditTenantQuarantined) != 1 || chain(AuditTenantQuarantined) != 1 {
		t.Fatalf("entered events: provider %d chain %d, want 1 each across two replicas and a restart", events(AuditTenantQuarantined), chain(AuditTenantQuarantined))
	}
	if n := count(t, pool, `SELECT count(*) FROM tenant_quarantine WHERE tenant = $1::uuid`, x); n != 2 {
		t.Fatalf("tenant_quarantine rows = %d, want one per replica", n)
	}
	restored = true
	s1.Recheck(ctx)
	if events(AuditTenantReleased) != 0 {
		t.Fatal("released while the other replica still holds the tenant")
	}
	s2.Recheck(ctx)
	if events(AuditTenantReleased) != 1 || chain(AuditTenantReleased) != 1 {
		t.Fatalf("released events: provider %d chain %d, want 1 each from the last holder", events(AuditTenantReleased), chain(AuditTenantReleased))
	}
	if n := count(t, pool, `SELECT count(*) FROM provider_audit_events WHERE action = $1 AND target = $2 AND data->>'replica' = $3`, AuditTenantReleased, x, r2); n != 1 {
		t.Fatal("the released event does not name the replica that made the transition")
	}
}

// DPR-385 on real Postgres: a provisioned silo loses one tenant-owned table
// after boot. No write of that tenant ever lands in public.<table> — the
// per-transaction guard refuses it at once — and the supervisor quarantines
// the tenant as silo_schema_incomplete within one check, without recreating
// the table behind the operator's back.
func TestDroppedSiloTableIsRefusedAndQuarantined(t *testing.T) {
	ctx := context.Background()
	pool := itPool(t)
	testsupport.LockPostgresPublicCatalog(t, pool)
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	x := mkTenant(t, pool, "d62-hollow-"+stamp, "siloed", "")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	prov := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := prov.Provision(ctx, x, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("provision: %v", err)
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
	if err != nil || len(required) < 10 {
		t.Fatalf("RequiredSiloTables = %d tables, %v", len(required), err)
	}
	tenancy.SetSiloRequiredTables(required)

	insert := func(name string) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(x)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO tests (tenant_id, name, type, target, interval_seconds, timeout_seconds, params, enabled)
				 VALUES ($1, $2, 'icmp', '192.0.2.1', 60, 5, '{}'::jsonb, true)`, x, name)
			return err
		})
	}
	s := NewQuarantineSupervisor(QuarantineConfig{Pool: pool, Checks: prov, Registry: q, Interval: 5 * time.Second,
		Replica: "d62-hollow-" + stamp, Log: log})
	s.list = func(context.Context) ([]IsolatedTenant, error) {
		return []IsolatedTenant{{ID: x, Model: "siloed", Status: "active"}}, nil
	}
	if held, err := s.Boot(ctx); err != nil || len(held) != 0 {
		t.Fatalf("Boot of a complete silo = %+v %v", held, err)
	}
	if err := insert("before"); err != nil {
		t.Fatalf("write to the complete silo: %v", err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE `+SchemaName(x)+`.tests CASCADE`); err != nil {
		t.Fatalf("drop the silo's tests table: %v", err)
	}
	if err := insert("after-drop"); !errors.Is(err, tenancy.ErrSiloSchemaMissing) {
		t.Fatalf("write after the silo lost its table = %v, want the per-transaction refusal", err)
	}
	s.Recheck(ctx)
	if err := q.Check(x); err == nil {
		t.Fatal("the tenant is not quarantined one check after its silo lost a table")
	}
	var reason string
	for _, e := range q.List() {
		if e.TenantID == x {
			reason = string(e.Reason)
		}
	}
	if reason != string(tenancy.QuarantineSchemaIncomplete) {
		t.Fatalf("quarantine reason = %q, want silo_schema_incomplete", reason)
	}
	s.Recheck(ctx)
	if n := count(t, pool, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = 'tests'`, SchemaName(x)); n != 0 {
		t.Fatal("the recheck recreated the dropped table behind the operator's back")
	}
	if n := count(t, pool, `SELECT count(*) FROM public.tests WHERE tenant_id = $1::uuid`, x); n != 0 {
		t.Fatalf("%d of the siloed tenant's tests landed in the pooled public.tests", n)
	}
	// The operator rolls the control plane: the startup catch-up recreates
	// the table (empty) and the tenant is complete again.
	if err := prov.CatchUp(ctx, x); err != nil {
		t.Fatalf("catch-up: %v", err)
	}
	s.Recheck(ctx)
	if err := q.Check(x); err != nil {
		t.Fatalf("still quarantined after the silo was made complete: %v", err)
	}
}
