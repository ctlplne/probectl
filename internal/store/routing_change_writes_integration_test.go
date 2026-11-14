// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"net/netip"
	"testing"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestOwnedRoutingChangesCommitOriginalAnnouncementsSelectedUpdatesAndWithdrawalsOnce(t *testing.T) {
	f := newRoleInputsFixture(t)
	for lane, tenant := range f.tenants {
		source := routingFixtureSource(f, lane)
		for _, kind := range []string{"adj_rib_in_pre_policy", "loc_rib"} {
			definition := routingViewFixture()
			if kind == "loc_rib" {
				definition = routingLookupDefinition(1)
			}
			ref := routingLookupBegin(t, f, source, definition)
			apply := func(sequence int64, value BGPRoutingChange, want string) {
				t.Helper()
				batch := BGPRoutingBatch{Sequence: sequence, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), Changes: []BGPRoutingChange{value}}
				result, err := routingFixtureApply(t, f, source, ref, batch, routingViewBudget())
				if err != nil || result.Status != want {
					t.Fatal("owned routing batch did not commit with its change", result, err)
				}
				if sequence == 2 {
					replayed, err := routingFixtureApply(t, f, source, ref, batch, routingViewBudget())
					if err != nil || replayed.Status != "replayed" {
						t.Fatal("original route replay was not idempotent", replayed, err)
					}
				}
			}
			first := routingChangeFixture()
			apply(1, first, "applied")
			second := routingChangeFixture()
			second.NextHops = []netip.Addr{netip.MustParseAddr("203.0.113.9")}
			apply(2, second, "applied")
			apply(3, BGPRoutingChange{Prefix: first.Prefix, HasPathID: first.HasPathID, PathID: first.PathID, Withdraw: true}, "applied")
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			if err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
				all, err := (ChangeEvents{}).List(ctx, sc, 1000)
				if err != nil {
					return err
				}
				var events []change.Event
				for _, event := range all {
					if event.Routing != nil && event.Routing.ViewID == ref.ID {
						events = append(events, event)
					}
				}
				if len(events) != 3 {
					t.Fatal("original route replay duplicated or lost change events", len(events))
				}
				bySequence := map[string]change.Event{}
				for _, event := range events {
					if event.TenantID != tenant || event.Target != source.RouterID || event.Prefix != first.Prefix.String() || event.Routing.View != kind {
						t.Fatal("route event lost canonical owner/view", event)
					}
					bySequence[event.Routing.Sequence] = event
				}
				if bySequence["1"].Routing.Action != "announcement" || bySequence["1"].Routing.PriorPresent {
					t.Fatal("first observation invented a previous route")
				}
				updated := bySequence["2"].Routing
				wantAction := "announcement"
				if kind == "loc_rib" {
					wantAction = "selected_route_update"
				}
				if updated.Action != wantAction || !updated.PriorPresent || !updated.PathChanged {
					t.Fatal("adjacent advertisement was mislabeled as a selected route or original path change was lost", updated)
				}
				withdrawn := bySequence["3"].Routing
				if withdrawn.Action != "withdrawal" || !withdrawn.PriorPresent || withdrawn.PathChanged {
					t.Fatal("withdrawal lost its original known path", withdrawn)
				}
				if err := (ChangeEvents{}).VerifyRoutingChangeReferencesInScope(ctx, sc, events, 64<<20, func(ctx context.Context, _ tenancy.Scope, current BGPRoutingSource, event change.Event) error {
					if current.TenantID != tenant || current.RouterID != event.Routing.RouterID {
						t.Fatal("change metadata replaced current tenant source authority")
					}
					return ctx.Err()
				}); err != nil {
					return err
				}
				return nil
			}); err != nil {
				t.Fatal("committed routing changes lost current source verification", err)
			}
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			fake := change.RouteReference{Version: 1}
			created, err := (ChangeEvents{}).Create(ctx, sc, change.Event{Source: "generic", Kind: change.KindRoute, Title: "Untrusted metadata", OccurredAt: source.ObservedAt, Routing: &fake})
			if err != nil {
				return err
			}
			if created.Routing != nil {
				t.Fatal("generic event creation manufactured an owned routing reference")
			}
			return nil
		})
	}
}

func TestOwnedRoutingChangesKeepIntermediateSamePrefixUpdatesInOneBatch(t *testing.T) {
	f := newRoleInputsFixture(t)
	for lane, tenant := range f.tenants {
		source := routingFixtureSource(f, lane)
		ref := routingLookupBegin(t, f, source, routingLookupDefinition(1))
		first := routingChangeFixture()
		second := routingChangeFixture()
		second.NextHops = []netip.Addr{netip.MustParseAddr("203.0.113.7")}
		withdrawn := BGPRoutingChange{Prefix: first.Prefix, HasPathID: first.HasPathID, PathID: first.PathID, Withdraw: true}
		batch := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), Changes: []BGPRoutingChange{first, second, withdrawn, first}}
		result, err := routingFixtureApply(t, f, source, ref, batch, routingViewBudget())
		if err != nil || result.Status != "applied" {
			t.Fatal("complete repeated-prefix batch refused", result, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			events, err := (ChangeEvents{}).List(ctx, sc, 100)
			if err != nil {
				return err
			}
			if len(events) != 4 {
				t.Fatal("current-RIB coalescing erased original updates", len(events))
			}
			byPosition := map[int]*change.RouteReference{}
			for _, event := range events {
				if event.Routing == nil || event.TenantID != tenant || event.Routing.Sequence != "1" {
					t.Fatal("batch lost original identity")
				}
				byPosition[event.Routing.UpdateIndex] = event.Routing
			}
			if len(byPosition) != 4 || byPosition[0].PriorPresent || byPosition[0].Action != "announcement" || !byPosition[1].PathChanged || byPosition[1].Action != "selected_route_update" || !byPosition[2].PriorPresent || byPosition[2].Action != "withdrawal" || byPosition[3].PriorPresent || byPosition[3].Action != "announcement" {
				t.Fatal("intermediate route transitions were reconstructed from final state", byPosition)
			}
			return nil
		})
	}
}
