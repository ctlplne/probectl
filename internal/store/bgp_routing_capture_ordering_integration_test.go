// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"reflect"
	"testing"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual tenant-role Postgres with modeled source data. This extends the
// original service proof; transport attestation and physical flow remain
// separate. A current route change must not reconstruct an earlier candidate.
func proveProvisionalCaptureKeepsOriginalRouteBeforeAuthenticatedPublication(t *testing.T, f *roleInputsFixture, service *BGPRoutingFlowCaptures, first [2]BGPRoutingCaptureReference, changes []BGPRoutingChange, input BGPRoutingFlowInput) {
	t.Helper()
	read := func(lane int, key [32]byte) (routingCaptureReceipt, bool) {
		t.Helper()
		var receipt routingCaptureReceipt
		var exists bool
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			receipt, exists, err = readRoutingCaptureInScope(ctx, sc, key, routingViewBudget())
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return receipt, exists
	}
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		original, exists := read(lane, first[lane].Key)
		if !exists || original.objects == nil {
			t.Fatal("missing original modeled source capture")
		}
		lookup, err := decodeRoutingCapture(ctx, *original.objects, routingViewBudget())
		if err != nil {
			t.Fatal(err)
		}
		raw := routingCaptureHash([]byte("raw-first complete original observation"))
		key, err := service.captureKey(ctx, "routing-flow", raw, input, routingViewBudget())
		if err != nil {
			t.Fatal(err)
		}
		var provisional BGPRoutingCaptureReference
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			generation, err := sourceepoch.SourceGenerationInScope(ctx, sc)
			if err == nil {
				provisional, err = retainRoutingCaptureIntentInScope(ctx, sc, key, *original.objects, generation, routingViewBudget())
			}
			return err
		})
		if pending, exists := read(lane, key); exists || pending.objects != nil {
			t.Fatal("unattested provisional candidate became canonical before sender evidence")
		}
		changed := routingChangeFixture()
		changed.Prefix = changes[lane].Prefix
		changed.Segments[1].Values[0] = uint32(65090 + lane)
		routingLookupApply(t, f, lookup.Source.Route.Source, lookup.Source.Route.View, BGPRoutingBatch{Sequence: 3, AFI: 1, SAFI: 1, Changes: []BGPRoutingChange{changed}})
		published, err := service.CaptureAuthenticated(ctx, "routing-flow", raw, input, routingViewBudget())
		if err != nil || published != provisional {
			t.Fatal("authenticated provisional publication changed original key or first clock", err)
		}
		frozen, exists := read(lane, key)
		if !exists || frozen.objects == nil {
			t.Fatal("exact sender evidence failed to publish its private candidate")
		}
		decoded, err := decodeRoutingCapture(ctx, *frozen.objects, routingViewBudget())
		if err != nil || !reflect.DeepEqual(decoded, lookup) {
			t.Fatal("authenticated provisional publication reconstructed the current route", err)
		}
		fresh, err := service.CaptureAuthenticated(ctx, "routing-flow", routingCaptureHash([]byte("new observation after actual modeled route change")), input, routingViewBudget())
		if err != nil {
			t.Fatal(err)
		}
		current, exists := read(lane, fresh.Key)
		if !exists || current.objects == nil {
			t.Fatal("current-route control retained no source capture")
		}
		decoded, err = decodeRoutingCapture(ctx, *current.objects, routingViewBudget())
		if err != nil || !reflect.DeepEqual(decoded.Source.Route.Paths, []BGPRoutingChange{changed}) {
			t.Fatal("current-route control did not exercise the changed source", err)
		}
		routingLookupApply(t, f, lookup.Source.Route.Source, lookup.Source.Route.View, BGPRoutingBatch{Sequence: 4, AFI: 1, SAFI: 1, Changes: []BGPRoutingChange{changes[lane]}})
	}
}

func proveProvisionalCaptureRefusesRetiredAuthority(t *testing.T, f *roleInputsFixture, service *BGPRoutingFlowCaptures, baseline BGPRoutingCaptureReference, input BGPRoutingFlowInput) {
	t.Helper()
	tenant := f.tenants[0]
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	read := func(key [32]byte) routingCaptureReceipt {
		t.Helper()
		var receipt routingCaptureReceipt
		err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var exists bool
			var err error
			receipt, exists, err = readRoutingCaptureInScope(ctx, sc, key, routingViewBudget())
			if err == nil && !exists {
				t.Fatal("missing final capture receipt")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return receipt
	}
	stage := func(raw [32]byte, objects *routingCaptureObjects) BGPRoutingCaptureReference {
		t.Helper()
		if objects == nil {
			t.Fatal("missing modeled provisional source")
		}
		key, err := service.captureKey(ctx, "routing-flow", raw, input, routingViewBudget())
		if err != nil {
			t.Fatal(err)
		}
		var ref BGPRoutingCaptureReference
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			generation, err := sourceepoch.SourceGenerationInScope(ctx, sc)
			if err == nil {
				ref, err = retainRoutingCaptureIntentInScope(ctx, sc, key, *objects, generation, routingViewBudget())
			}
			return err
		})
		return ref
	}
	checkUnavailable := func(raw [32]byte, first BGPRoutingCaptureReference, marker string) {
		t.Helper()
		got, err := service.CaptureAuthenticated(ctx, "routing-flow", raw, input, routingViewBudget())
		if err != nil || got != first {
			t.Fatal("retired provisional finalization lost its original first clock", err)
		}
		if receipt := read(first.Key); receipt.outcome != "unavailable" || receipt.objects != nil {
			t.Fatal(marker)
		}
	}
	old := read(baseline.Key)
	rawEpoch := routingCaptureHash([]byte("raw before validated erasure epoch"))
	beforeEpoch := stage(rawEpoch, old.objects)
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sourceepoch.SourceGenerationInScope(ctx, sc); err != nil {
			return err
		}
		if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
			return err
		}
		return sourceepoch.InvalidateSourceGenerationInScope(ctx, sc)
	})
	checkUnavailable(rawEpoch, beforeEpoch, "expired provisional epoch became canonical after erasure")

	newBaseline, err := service.CaptureAuthenticated(ctx, "routing-flow", routingCaptureHash([]byte("current source after erasure epoch")), input, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	current := read(newBaseline.Key)
	rawErased := routingCaptureHash([]byte("raw provisional payload erased before witness"))
	beforeErase := stage(rawErased, current.objects)
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM bgp_flow_capture_objects WHERE tenant_id=$1 AND digest=$2`, tenant, current.objects.clocks.digest[:])
		return err
	})
	checkUnavailable(rawErased, beforeErase, "erased provisional payload was rebuilt from the current route")

	newBaseline, err = service.CaptureAuthenticated(ctx, "routing-flow", routingCaptureHash([]byte("new legitimate source reuses erased content")), input, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	current = read(newBaseline.Key)
	checkUnavailable(rawErased, beforeErase, "new legitimate capture revived erased provisional evidence")
	rawRevoked := routingCaptureHash([]byte("raw candidate whose source credential was revoked"))
	beforeRevocation := stage(rawRevoked, current.objects)
	if _, _, err := NewAgentIdentities(f.pool).RevokeAgent(t.Context(), tenant, "routing-flow", "provisional-source-test"); err != nil {
		t.Fatal(err)
	}
	checkUnavailable(rawRevoked, beforeRevocation, "revoked source finalized a private provisional capture")
}
