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
		Planes: []string{"eu"}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
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

func count(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}
