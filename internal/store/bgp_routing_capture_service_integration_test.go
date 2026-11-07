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
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoutingCaptureServiceSealsCurrentExporterBeforeRetriesAndSourceChanges(t *testing.T) {
	f, changes, serials, input := newRoutingFlowCaptureFixture(t)
	// All service phases are sequential tenant transactions. A legitimate
	// single-connection deployment needs no phantom multi-connection minimum.
	config := f.pool.Config().Copy()
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	service := NewBGPRoutingFlowCaptures(pool)
	rawDigest := routingCaptureHash([]byte("same verified source observation"))
	var first [2]BGPRoutingCaptureReference
	read := func(lane int, flowKey [32]byte) routingCaptureReceipt {
		t.Helper()
		var receipt routingCaptureReceipt
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var exists bool
			var err error
			receipt, exists, err = readRoutingCaptureInScope(ctx, sc, flowKey, routingViewBudget())
			if err == nil && !exists {
				t.Fatal("capture service omitted its durable first receipt")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return receipt
	}
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		first[lane], err = service.CaptureAuthenticated(ctx, "routing-flow", rawDigest, input, routingViewBudget())
		if err != nil || first[lane].Key == ([32]byte{}) || first[lane].CapturedAt.IsZero() {
			t.Fatal("current owned flow did not seal its routing capture", lane, err)
		}
		receipt := read(lane, first[lane].Key)
		if receipt.objects == nil {
			t.Fatal("owned current flow retained no complete routing evidence")
		}
		got, err := decodeRoutingCapture(ctx, *receipt.objects, routingViewBudget())
		if err != nil || got.Owner.TenantID != tenant || !reflect.DeepEqual(got.Source.Route.Paths, []BGPRoutingChange{changes[lane]}) || !reflect.DeepEqual(got.Destination.Route.Paths, got.Source.Route.Paths) {
			t.Fatal("capture adapter lost complete owned paths or crossed tenant", lane, err)
		}
	}
	proveCapturedRoutingReaderRequiresCurrentContextAndOriginalReference(t, f, first, rawDigest, input, changes)
	proveProvisionalCaptureKeepsOriginalRouteBeforeAuthenticatedPublication(t, f, service, first, changes, input)
	proveCompleteRawCaptureBatchKeepsTenantAndAtomicRefusal(t, f, service, input)
	// The raw lane can resolve a positive certificate-authored witness, but
	// payload IDs alone must seal unavailable despite a fully live owned RIB.
	witnessed, err := service.ResolveWitness(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), "routing-flow", rawDigest, input, routingViewBudget())
	if err != nil || witnessed != first[0] {
		t.Fatal("raw consumer lost independently authenticated first witness", err)
	}
	rawOnly := routingCaptureHash([]byte("raw payload claiming a registered live exporter"))
	rawReference, err := service.ResolveWitness(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), "routing-flow", rawOnly, input, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	if receipt := read(0, rawReference.Key); receipt.outcome != "unavailable" || receipt.objects != nil {
		t.Fatal("bus claimed sender created a positive canonical capture")
	}
	if late, err := service.CaptureAuthenticated(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), "routing-flow", rawOnly, input, routingViewBudget()); err != nil || late != rawReference {
		t.Fatal("late authenticated proof changed first raw capture clock", err)
	}
	if receipt := read(0, rawReference.Key); receipt.outcome != "unavailable" || receipt.objects != nil {
		t.Fatal("late authenticated proof refilled an unavailable raw capture")
	}
	if got, err := service.CaptureAuthenticated(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), "other-authenticated-agent", rawDigest, input, routingViewBudget()); !errors.Is(err, entity.ErrScopeMismatch) || got != (BGPRoutingCaptureReference{}) {
		t.Fatal("authenticated sender selected another agent's canonical router", err)
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id='routing-flow' AND source_kind='flow_exporter'`, f.tenants[0])
		return err
	})
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0]))
	requireRetiredRoutingReaderUnavailable(t, f, 0, rawDigest, input, first[0])
	if retry, err := service.CaptureAuthenticated(ctx, "routing-flow", rawDigest, input, routingViewBudget()); err != nil || retry.Key != first[0].Key || !retry.CapturedAt.Equal(first[0].CapturedAt) {
		t.Fatal("retry re-read current input or changed its first capture clock", err)
	}
	unavailableKey := routingCaptureHash([]byte("unattested first observation"))
	unavailable, err := service.CaptureAuthenticated(ctx, "routing-flow", unavailableKey, input, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	if receipt := read(0, unavailable.Key); receipt.outcome != "unavailable" || receipt.objects != nil {
		t.Fatal("missing current exporter invented routing attribution")
	}
	routingFlowFixtureAssignment(t, f, f.tenants[0], "routing-flow", input.Exporter.String())
	routingFlowFixtureEvidence(t, f, f.tenants[0], "routing-flow", serials[0], input.Exporter.String())
	if _, err := service.CaptureAuthenticated(ctx, "routing-flow", unavailableKey, input, routingViewBudget()); err != nil {
		t.Fatal(err)
	}
	if receipt := read(0, unavailable.Key); receipt.outcome != "unavailable" || receipt.objects != nil {
		t.Fatal("fresh source evidence rewrote an unavailable first capture")
	}
	freshKey := routingCaptureHash([]byte("fresh observation after source restoration"))
	fresh, err := service.CaptureAuthenticated(ctx, "routing-flow", freshKey, input, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	if receipt := read(0, fresh.Key); receipt.outcome != "captured" || receipt.objects == nil {
		t.Fatal("new observation did not capture restored current source")
	}
	proveProvisionalCaptureRefusesRetiredAuthority(t, f, service, fresh, input)
	if _, err := f.pool.Exec(t.Context(), `UPDATE tenants SET status='offboarding' WHERE id=$1`, f.tenants[1]); err != nil {
		t.Fatal(err)
	}
	var rawPostgres *pgconn.PgError
	if got, err := service.ResolveWitness(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[1])), "routing-flow", rawDigest, input, routingViewBudget()); !errors.As(err, &rawPostgres) || rawPostgres.Code != "55000" || got != (BGPRoutingCaptureReference{}) {
		t.Fatal("offboarding raw lookup exposed first witness before tenant fence", err)
	}
	if got, err := service.StageRaw(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[1])), "routing-flow", []entity.FlowCaptureWitness{{RawDigest: rawDigest, Input: input}}, routingViewBudget()); !errors.As(err, &rawPostgres) || rawPostgres.Code != "55000" || got != nil {
		t.Fatal("offboarding raw staging exposed first metadata before tenant fence", err)
	}
	var postgres *pgconn.PgError
	if got, err := service.CaptureAuthenticated(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[1])), "routing-flow", rawDigest, input, routingViewBudget()); !errors.As(err, &postgres) || postgres.Code != "55000" || got != (BGPRoutingCaptureReference{}) {
		t.Fatal("offboarding capture exposed an existing reference before its tenant fence", err)
	}
}
