// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// hybridTestRouter answers like ee/silo's router does for a hybrid tenant:
// isolated data planes (bus namespace, object prefix) but pooled Postgres
// control state, so the tenant's trap rows live in public.device_traps under
// row security. Every other tenant is pooled.
type hybridTestRouter struct{ hybrid string }

func (r hybridTestRouter) TargetsFor(_ context.Context, tenantID string) (tenancy.Targets, error) {
	if tenantID == r.hybrid {
		return tenancy.Targets{Model: tenancy.IsolationHybrid, BusNamespace: "t-hybrid", ObjectPrefix: tenancy.SiloObjectPrefix(tenantID)}, nil
	}
	return tenancy.Targets{Model: tenancy.IsolationPooled}, nil
}
func (hybridTestRouter) BusNamespaces(context.Context) ([]string, error) { return nil, nil }
func (hybridTestRouter) BusNamespaceTenants(context.Context) (map[string]string, error) {
	return nil, nil
}

type trapTenants struct {
	pool   *pgxpool.Pool
	a, b   string // a pooled, b hybrid
	traps  *DeviceTraps
	stamps time.Time
}

func setupTrapTenants(t *testing.T) *trapTenants {
	t.Helper()
	ctx := context.Background()
	pool := deviceNeighborIsolationPool(t) // migrated pool, skips without Postgres
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "traps-a-"+suffix, "Traps A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "traps-b-"+suffix, "Traps B")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tenants SET isolation_model = 'hybrid' WHERE id = $1`, b.ID); err != nil {
		t.Fatal(err)
	}
	prev := tenancy.CurrentRouter()
	tenancy.SetRouter(hybridTestRouter{hybrid: b.ID})
	t.Cleanup(func() { tenancy.SetRouter(prev) })
	return &trapTenants{pool: pool, a: a.ID, b: b.ID, traps: NewDeviceTraps(pool), stamps: time.Now().UTC().Truncate(time.Microsecond)}
}

func (tt *trapTenants) record(tenant, agent, addr, fp string, at time.Time) device.TrapRecord {
	return device.TrapRecord{
		TenantID: tenant, AgentID: agent, DeviceAddress: addr, SourceAddress: addr,
		AuthPrincipal: agent + "-ro", Version: "snmpv3", Kind: "snmp.trap.link_down", Severity: "warning",
		TrapOID: ".1.3.6.1.6.3.1.1.5.3", IfIndex: 2, Fingerprint: fp, ObservedAt: at, ReceivedAt: at,
		VarBinds: []device.TrapVarBind{{OID: ".1.3.6.1.2.1.2.2.1.1.2", Type: "Integer", Value: "2"},
			{OID: ".1.3.6.1.2.1.31.1.1.1.18.2", Type: "OctetString", Value: "uplink of " + tenant}},
	}
}

func (tt *trapTenants) mustRecord(t *testing.T, rec device.TrapRecord) bool {
	t.Helper()
	inserted, err := tt.traps.RecordTrapEvent(context.Background(), rec.TenantID, rec)
	if err != nil {
		t.Fatalf("record trap %s for %s: %v", rec.Fingerprint, rec.TenantID, err)
	}
	return inserted
}

// TestDeviceTrapStoreIsTenantIsolated is the storage-layer isolation receipt
// for the trap read model (D-60): a pooled and a hybrid tenant each see only
// their own traps through the store, a predicate-free count as the app role
// scoped to a tenant sees only its rows, and neither a write nor a delete can
// cross the boundary.
func TestDeviceTrapStoreIsTenantIsolated(t *testing.T) {
	ctx := context.Background()
	tt := setupTrapTenants(t)
	now := tt.stamps
	tt.mustRecord(t, tt.record(tt.a, "agent-a", "10.0.0.1", "fp-a-1", now.Add(-2*time.Minute)))
	tt.mustRecord(t, tt.record(tt.a, "agent-a", "10.0.0.2", "fp-a-2", now.Add(-time.Minute)))
	// B's device shares A's first address: a lost tenant scope would merge them.
	tt.mustRecord(t, tt.record(tt.b, "agent-b", "10.0.0.1", "fp-b-1", now))

	for _, tc := range []struct {
		tenant, other string
		want          int
	}{{tt.a, tt.b, 2}, {tt.b, tt.a, 1}} {
		rows, truncated, err := tt.traps.ListTrapEvents(ctx, tc.tenant, device.TrapFilter{Limit: device.MaxTrapRead})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != tc.want || truncated {
			t.Fatalf("tenant %s listed %d traps (truncated %v), want %d", tc.tenant, len(rows), truncated, tc.want)
		}
		for _, r := range rows {
			if r.TenantID != tc.tenant || strings.Contains(r.VarBinds[1].Value, tc.other) {
				t.Fatalf("tenant %s read another tenant's trap: %+v", tc.tenant, r)
			}
		}
		// The shared address filtered for the other tenant's device returns only own rows.
		rows, _, err = tt.traps.ListTrapEvents(ctx, tc.tenant, device.TrapFilter{Device: "10.0.0.1"})
		if err != nil || len(rows) != 1 || rows[0].TenantID != tc.tenant {
			t.Fatalf("tenant %s device=10.0.0.1 = %+v err=%v, want only its own trap", tc.tenant, rows, err)
		}
	}

	// Predicate-free reads/writes as the app role scoped to A see only A.
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tt.a)), tt.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var seen int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM device_traps`).Scan(&seen); err != nil {
			return err
		}
		if seen != 2 {
			t.Fatalf("a predicate-free count as A's scoped app role saw %d trap rows, want A's 2", seen)
		}
		tag, err := sc.Q.Exec(ctx, `DELETE FROM device_traps WHERE tenant_id = $1`, tt.b)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			t.Fatal("tenant A's scope deleted tenant B's traps")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tt.a)), tt.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO device_traps (tenant_id, agent_id, fingerprint, device_address, version, kind, severity, observed_at)
			VALUES ($1, 'agent-x', 'forged', '10.9.9.9', 'snmpv2c', 'snmp.trap', 'info', now())`, tt.b)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("an insert for tenant B under A's scope = %v, want a row-security violation (42501)", err)
	}
	var total int
	if err := tt.pool.QueryRow(ctx, `SELECT count(*) FROM device_traps WHERE tenant_id = ANY($1::uuid[])`, []string{tt.a, tt.b}).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("both tenants hold %d trap rows, want 3 (nothing forged, nothing deleted)", total)
	}

	// The store refuses a record whose tenant disagrees with the write scope.
	if _, err := tt.traps.RecordTrapEvent(ctx, tt.a, tt.record(tt.b, "agent-b", "10.0.0.3", "fp-x", now)); err == nil {
		t.Fatal("RecordTrapEvent stored tenant B's record under tenant A's scope")
	}
}

func TestDeviceTrapStoreIsIdempotentFilteredAndBounded(t *testing.T) {
	ctx := context.Background()
	tt := setupTrapTenants(t)
	now := tt.stamps
	rec := tt.record(tt.a, "agent-a", "10.0.0.1", "fp-1", now.Add(-10*time.Minute))
	if !tt.mustRecord(t, rec) || tt.mustRecord(t, rec) {
		t.Fatal("a redelivered trap (same agent + fingerprint) must insert exactly once")
	}
	// The same fingerprint from another agent is another trap.
	other := rec
	other.AgentID = "agent-a2"
	if !tt.mustRecord(t, other) {
		t.Fatal("the same fingerprint from a second agent was treated as a duplicate")
	}
	tt.mustRecord(t, tt.record(tt.a, "agent-a", "10.0.0.2", "fp-2", now.Add(-5*time.Minute)))
	tt.mustRecord(t, tt.record(tt.a, "agent-a", "10.0.0.2", "fp-3", now))

	rows, _, err := tt.traps.ListTrapEvents(ctx, tt.a, device.TrapFilter{Since: now.Add(-6 * time.Minute), Until: now})
	if err != nil || len(rows) != 1 || rows[0].Fingerprint != "fp-2" {
		t.Fatalf("since/until window = %+v err=%v, want fp-2 only", rows, err)
	}
	rows, truncated, err := tt.traps.ListTrapEvents(ctx, tt.a, device.TrapFilter{Limit: 2})
	if err != nil || len(rows) != 2 || !truncated || rows[0].Fingerprint != "fp-3" {
		t.Fatalf("limit 2 = %+v truncated=%v err=%v, want the newest two and truncated", rows, truncated, err)
	}
	if rows[0].TrapName != "linkDown" || rows[0].IfIndex != 2 || len(rows[0].VarBinds) != 2 || rows[0].AuthPrincipal != "agent-a-ro" {
		t.Fatalf("round-tripped row = %+v", rows[0])
	}

	// Retention: a row older than device.TrapRetention is pruned by the next write.
	if _, err := tt.pool.Exec(ctx, `UPDATE device_traps SET received_at = now() - interval '31 days' WHERE tenant_id = $1 AND fingerprint = 'fp-1'`, tt.a); err != nil {
		t.Fatal(err)
	}
	// Count cap: fill the tenant to the cap with old rows, then one more write.
	if _, err := tt.pool.Exec(ctx, `
		INSERT INTO device_traps (tenant_id, agent_id, fingerprint, device_address, version, kind, severity, observed_at, received_at)
		SELECT $1, 'agent-bulk', 'bulk-' || g, '10.1.0.1', 'snmpv2c', 'snmp.trap', 'info', now() - interval '1 day', now() - interval '1 day' - g * interval '1 second'
		  FROM generate_series(1, $2::int) AS g`, tt.a, device.MaxTrapsPerTenant); err != nil {
		t.Fatal(err)
	}
	tt.mustRecord(t, tt.record(tt.a, "agent-a", "10.0.0.9", "fp-newest", now.Add(time.Second)))
	var count, aged, newest int
	if err := tt.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE fingerprint = 'fp-1' AND agent_id = 'agent-a'),
		count(*) FILTER (WHERE fingerprint = 'fp-newest') FROM device_traps WHERE tenant_id = $1`, tt.a).Scan(&count, &aged, &newest); err != nil {
		t.Fatal(err)
	}
	if count != device.MaxTrapsPerTenant || aged != 0 || newest != 1 {
		t.Fatalf("after the bounded write: %d rows (cap %d), aged row kept=%d, newest kept=%d", count, device.MaxTrapsPerTenant, aged, newest)
	}
	// B is untouched by A's pruning.
	tt.mustRecord(t, tt.record(tt.b, "agent-b", "10.0.0.1", "fp-b", now))
	rowsB, _, err := tt.traps.ListTrapEvents(ctx, tt.b, device.TrapFilter{})
	if err != nil || len(rowsB) != 1 {
		t.Fatalf("tenant B rows = %+v err=%v", rowsB, err)
	}
	// A read beyond the hard cap is clamped.
	rows, truncated, err = tt.traps.ListTrapEvents(ctx, tt.a, device.TrapFilter{Limit: 100_000})
	if err != nil || len(rows) != device.MaxTrapRead || !truncated {
		t.Fatalf("limit 100000 returned %d rows truncated=%v err=%v, want the %d-row hard cap", len(rows), truncated, err, device.MaxTrapRead)
	}
}

// TestDeviceTrapStoreRefusesFencedTenantWrites: the generic tenant write fence
// (0086) is installed on device_traps from its first migration, so a suspended
// tenant's trap write fails in PostgreSQL itself.
func TestDeviceTrapStoreRefusesFencedTenantWrites(t *testing.T) {
	ctx := context.Background()
	tt := setupTrapTenants(t)
	var triggers int
	if err := tt.pool.QueryRow(ctx, `SELECT count(*) FROM pg_trigger WHERE tgrelid = 'public.device_traps'::regclass AND tgname = 'tenant_write_fence' AND tgenabled = 'A'`).Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	if triggers != 1 {
		t.Fatalf("device_traps carries %d enabled-always tenant_write_fence triggers, want 1", triggers)
	}
}
