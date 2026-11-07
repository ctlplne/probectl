// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoutingBindingManifestKeepsExactSelectorsAndRefusesAmbiguity(t *testing.T) {
	binding := routingSourceBinding{ContextID: "11111111-1111-4111-8111-111111111111", RouterID: "22222222-2222-4222-8222-222222222222", Distinguisher: "ffffffffffffffff", BGPIdentifier: "0.0.0.0", Families: []uint16{2, 1}}
	got, err := prepareRoutingBindings(t.Context(), []routingSourceBinding{binding}, routingViewBudget())
	if err != nil || len(got) != 1 || got[0].ID == "" || got[0].Distinguisher != binding.Distinguisher || got[0].BGPIdentifier != binding.BGPIdentifier || !reflect.DeepEqual(got[0].Families, []uint16{1, 2}) || binding.Families[0] != 2 {
		t.Fatal("operator selector lost complete wire values or owned family copies", err)
	}
	upper := binding
	upper.Distinguisher = "FFFFFFFFFFFFFFFF"
	if normalized, err := prepareRoutingBindings(t.Context(), []routingSourceBinding{upper}, routingViewBudget()); err != nil || normalized[0].Distinguisher != binding.Distinguisher {
		t.Fatal("operator wire selector case changed the supported value", err)
	}
	unknown := binding
	unknown.SourceFormat = "future-unknown"
	if out, err := prepareRoutingBindings(t.Context(), []routingSourceBinding{unknown}, routingViewBudget()); err == nil || out != nil {
		t.Fatal("unknown routing serializer acquired operator authority")
	}
	got[0].Families[0] = 2
	if !reflect.DeepEqual(binding.Families, []uint16{2, 1}) {
		t.Fatal("prepared routing manifest aliased operator input")
	}
	for _, change := range []func(*routingSourceBinding){
		func(b *routingSourceBinding) { b.ContextID = "foreign-context" },
		func(b *routingSourceBinding) { b.RouterID = "" },
		func(b *routingSourceBinding) { b.Distinguisher = "gggggggggggggggg" },
		func(b *routingSourceBinding) { b.Distinguisher = "0000" },
		func(b *routingSourceBinding) { b.BGPIdentifier = "::ffff:192.0.2.1" },
		func(b *routingSourceBinding) { b.Families = nil },
		func(b *routingSourceBinding) { b.Families = []uint16{1, 1} },
		func(b *routingSourceBinding) { b.Families = []uint16{3} },
		func(b *routingSourceBinding) { b.SourceFormat = "future-unknown" },
	} {
		bad := binding
		change(&bad)
		if out, err := prepareRoutingBindings(t.Context(), []routingSourceBinding{binding, bad}, routingViewBudget()); err == nil || out != nil {
			t.Fatal("routing selector validation returned a partial or ambiguous manifest")
		}
	}
	if out, err := prepareRoutingBindings(t.Context(), []routingSourceBinding{binding, binding}, routingViewBudget()); err == nil || out != nil {
		t.Fatal("duplicate wire selectors acquired competing context bindings")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if out, err := prepareRoutingBindings(ctx, nil, routingViewBudget()); err == nil || out != nil {
		t.Fatal("canceled empty manifest authorized a routing reset")
	}
	if out, err := prepareRoutingBindings(ctx, []routingSourceBinding{binding}, routingViewBudget()); err == nil || out != nil {
		t.Fatal("canceled routing manifest returned bindings")
	}
	if out, err := prepareRoutingBindings(t.Context(), []routingSourceBinding{binding}, BGPRoutingBudget{MemoryBytes: 1, WorkUnits: 1, StateBytes: 1}); err == nil || out != nil {
		t.Fatal("unadmitted routing manifest returned bindings")
	}
	if _, err := putRoutingBindings(tenancy.WithTenant(t.Context(), "red"), tenancy.Scope{Tenant: "blue"}, "", "", "", "", nil, routingViewBudget()); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatal("foreign routing assignment reached storage")
	}
}
