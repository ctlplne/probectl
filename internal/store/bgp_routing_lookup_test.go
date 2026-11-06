// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestBGPRoutingLookupRequiresTenantExactViewAndWholeAdmissionBeforeStorage(t *testing.T) {
	tenant := "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	sc := tenancy.Scope{Tenant: tenancy.ID(tenant)}
	source := BGPRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}, RouterID: "33333333-3333-4333-8333-333333333333", CollectorAgentID: "collector", SourceRef: "router", SenderSerial: "sender", OriginSerial: "origin", ObservedAt: time.Now()}
	ref := BGPRoutingViewRef{ID: "44444444-4444-4444-8444-444444444444", Generation: "55555555-5555-4555-8555-555555555555"}
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		change func(*BGPRoutingSource, *BGPRoutingViewRef, *netip.Addr, *BGPRoutingBudget)
		want   error
	}{
		{name: "missing-tenant", ctx: t.Context(), want: entity.ErrScopeMismatch},
		{name: "foreign-tenant", ctx: ctx, change: func(s *BGPRoutingSource, _ *BGPRoutingViewRef, _ *netip.Addr, _ *BGPRoutingBudget) {
			s.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		}, want: entity.ErrScopeMismatch},
		{name: "invalid-ref", ctx: ctx, change: func(_ *BGPRoutingSource, r *BGPRoutingViewRef, _ *netip.Addr, _ *BGPRoutingBudget) {
			r.Generation = "other"
		}, want: ErrBGPRoutingView},
		{name: "missing-address", ctx: ctx, change: func(_ *BGPRoutingSource, _ *BGPRoutingViewRef, a *netip.Addr, _ *BGPRoutingBudget) { *a = netip.Addr{} }, want: ErrBGPRoutingView},
		{name: "scoped-address", ctx: ctx, change: func(_ *BGPRoutingSource, _ *BGPRoutingViewRef, a *netip.Addr, _ *BGPRoutingBudget) {
			*a = netip.MustParseAddr("fe80::1%eth0")
		}, want: ErrBGPRoutingView},
		{name: "whole-memory", ctx: ctx, change: func(_ *BGPRoutingSource, _ *BGPRoutingViewRef, _ *netip.Addr, b *BGPRoutingBudget) { b.MemoryBytes = 1 }, want: ErrBGPRoutingBudget},
		{name: "whole-work", ctx: ctx, change: func(_ *BGPRoutingSource, _ *BGPRoutingViewRef, _ *netip.Addr, b *BGPRoutingBudget) { b.WorkUnits = 1 }, want: ErrBGPRoutingBudget},
		{name: "missing-storage", ctx: ctx, want: ErrBGPRoutingSourceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, a, b := source, ref, netip.MustParseAddr("192.0.2.1"), routingViewBudget()
			if tc.change != nil {
				tc.change(&s, &r, &a, &b)
			}
			got, err := (BGPRouting{}).lookupViewInScope(tc.ctx, sc, s, r, a, b)
			if !errors.Is(err, tc.want) || got.Paths != nil || got.Source.TenantID != "" || got.Prefix.IsValid() {
				t.Fatal("routing lookup exposed partial or foreign state before storage", got, err)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (BGPRouting{}).lookupViewInScope(canceled, sc, source, ref, netip.MustParseAddr("192.0.2.1"), routingViewBudget()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
