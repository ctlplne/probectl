// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package billing

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/ee/silo"
	"github.com/ctlplne/probectl/internal/notify"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAutotaskAdjustmentRecoveryKeepsTenantClaimsSeparate(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	aID, bID := uuid.NewString(), uuid.NewString()
	contextID := uuid.NewString()
	devices := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	seedBillableInventory(t, pool, aID, contextID, devices, 1, 1)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=ANY($1::uuid[])", []string{aID, bID}); err != nil {
			t.Error(err)
		}
	})
	seedAutotaskBillingSilo(t, pool, bID, contextID, devices)

	mapping := AutotaskContractMapping{CompanyID: 7, ContractID: 9, RecurringType: 6, DevicesServiceID: 12, AgentsServiceID: 13}
	alpha := &autotaskBillingFixture{mapping: mapping, counts: PSAQuantities{Agents: 1}, calendarEnd: "2026-11-25T00:00:00Z"}
	beta := &autotaskBillingFixture{mapping: mapping, counts: PSAQuantities{Devices: 1, Agents: 1}, calendarEnd: "2026-11-25"}
	server, _ := autotaskBillingServer(t, map[string]*autotaskBillingFixture{"alpha": alpha, "beta": beta})
	reader := func(name, tenant string) *AutotaskBillingReader {
		t.Helper()
		r, err := NewAutotaskBillingReader(tenant, server.URL+autotaskFixtureZone, mapping, notify.AutotaskCredentials{
			UserName: name, Secret: name + "-fixture", IntegrationCode: "fixture-integration",
		}, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	leftReader, rightReader := reader("alpha", aID), reader("beta", bID)
	aCtx := tenancy.WithTenant(t.Context(), tenancy.ID(aID))
	bCtx := tenancy.WithTenant(t.Context(), tenancy.ID(bID))
	for _, owner := range []struct {
		ctx    context.Context
		schema string
	}{{aCtx, "public"}, {bCtx, silo.SchemaName(bID)}} {
		if err := tenancy.InTenantReadSnapshot(owner.ctx, pool, func(ctx context.Context, scope tenancy.Scope) error {
			var schema string
			var canUpdate bool
			if err := scope.Q.QueryRow(ctx, `SELECT current_schema(),
				has_table_privilege('psa_autotask_adjustment_pending', 'UPDATE')`).Scan(&schema, &canUpdate); err != nil {
				return err
			}
			if schema != owner.schema || canUpdate {
				t.Errorf("billing journal schema = %q, want %q, app UPDATE grant = %t", schema, owner.schema, canUpdate)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	journal := autotaskAdjustmentJournal{pool: pool}
	key := autotaskAdjustmentKey{CompanyID: 7, ContractID: 9, ContractServiceID: 12}
	intent := autotaskAdjustment{Key: key, EffectiveAt: autotaskBillingInstant, Previous: 0, Desired: 1}
	left, err := journal.reserve(aCtx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if collision, err := journal.reserve(aCtx, intent); collision != nil || !errors.Is(err, errAutotaskAdjustmentPending) {
		t.Fatal("a repeated reservation acquired another send claim", err)
	}
	right, err := journal.reserve(bCtx, intent)
	if err != nil || right.Tenant == left.Tenant {
		t.Fatal("the same provider service ID did not keep a separate tenant claim", err)
	}
	if closed, err := journal.resolve(bCtx, *left, autotaskQuantityObserved); closed || !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatal("a sibling tenant closed the foreign claim", err)
	}

	worker := &PSASync{pool: pool, canWrite: func() bool { return true }}
	if err := worker.sendAutotaskAdjustment(aCtx, leftReader, journal, *left); err == nil || alpha.adjustmentCalls.Load() != 1 {
		t.Fatal("the unavailable response did not leave an uncertain adjustment", err)
	}
	restarted := &PSASync{pool: pool, canWrite: func() bool { return true }}
	if err := restarted.syncAutotaskService(aCtx, leftReader, mapping.DevicesServiceID); !errors.Is(err, errAutotaskAdjustmentUnconfirmed) ||
		alpha.adjustmentCalls.Load() != 1 {
		t.Fatal("a restart retried an additive adjustment before observing it", err)
	}
	beta.unavailableService.Store(mapping.AgentsServiceID)
	if err := restarted.syncAutotaskService(bCtx, rightReader, mapping.DevicesServiceID); err != nil {
		t.Fatal("beta's device readback could not resolve its own claim without the unavailable agent service", err)
	}
	checkPending := func(ctx context.Context, expected int64) {
		t.Helper()
		err := tenancy.InTenant(ctx, pool, func(ctx context.Context, scope tenancy.Scope) error {
			pending, err := readAutotaskAdjustment(ctx, scope, key)
			if err != nil {
				return err
			}
			if expected == 0 && pending != nil || expected > 0 && (pending == nil || pending.Sequence != expected) {
				t.Error("journal state crossed tenants or attempt sequences")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	checkPending(aCtx, left.Sequence)
	checkPending(bCtx, 0)
	alpha.appliedDeviceUnit.Store(true)
	if err := restarted.syncAutotaskService(aCtx, leftReader, mapping.DevicesServiceID); err != nil {
		t.Fatal("observed service units did not close the pending attempt", err)
	}
	checkPending(aCtx, 0)
	intent.Previous, intent.Desired = 1, 2
	newer, err := journal.reserve(aCtx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if closed, err := journal.resolve(aCtx, *left, autotaskQuantityObserved); closed || err != nil {
		t.Fatal("a stale outcome closed a newer attempt", err)
	}
	checkPending(aCtx, newer.Sequence)
	if alpha.adjustmentCalls.Load() != 1 || beta.adjustmentCalls.Load() != 0 {
		t.Fatal("an observation sent an additional adjustment")
	}
}

func seedAutotaskBillingSilo(t *testing.T, pool *pgxpool.Pool, tenant, contextID string, devices []string) {
	t.Helper()
	ctx := t.Context()
	const model = tenancy.IsolationSiloed
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,slug,name,isolation_model)
		VALUES ($1::uuid,$1::uuid::text,$1::uuid::text,$2)`, tenant, model); err != nil {
		t.Fatal(err)
	}
	provisioner := silo.NewProvisioner(pool, silo.CHPlanes{}, nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		if err := provisioner.Teardown(context.Background(), tenant, "", model); err != nil {
			t.Error(err)
		}
	})
	if err := provisioner.Provision(ctx, tenant, "", model); err != nil {
		t.Fatal(err)
	}
	table := pgx.Identifier{silo.SchemaName(tenant), "psa_autotask_adjustment_pending"}.Sanitize()
	var canUpdate bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('probectl_app', $1::text, 'UPDATE')`, table).Scan(&canUpdate); err != nil {
		t.Fatal(err)
	}
	if canUpdate {
		t.Fatal("new silo allows the app role to rewrite a pending adjustment")
	}
	// Model the generic grant restored from an older silo before catch-up.
	if _, err := pool.Exec(ctx, "GRANT UPDATE ON "+table+" TO probectl_app"); err != nil {
		t.Fatal(err)
	}
	if err := provisioner.CatchUpSchema(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	required, err := silo.RequiredSiloTables(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	previousRouter := tenancy.CurrentRouter()
	t.Cleanup(func() { tenancy.SetRouter(previousRouter); tenancy.SetSiloRequiredTables(nil) })
	tenancy.SetRouter(silo.NewRouter(pool, nil, 0))
	tenancy.SetSiloRequiredTables(required)
	seedBillableInventoryRows(t, pool, tenant, contextID, devices, 2, 1)
}
