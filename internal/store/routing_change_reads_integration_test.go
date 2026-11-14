// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real application-role PostgreSQL/RLS and current issued-identity/source
// records. Accepted routing metadata is modeled; no physical BMP sender is
// claimed by this reader test.
func TestOwnedRoutingChangeReadsKeepCompleteCurrentSourcesAndTenantIsolation(t *testing.T) {
	f := newRoleInputsFixture(t)
	byTenant := map[string][]change.Event{}
	const population = 5001
	for lane, tenant := range f.tenants {
		source := routingFixtureSource(f, lane)
		view := routingFixtureBegin(t, f, source)
		born := source.ObservedAt
		source.ObservedAt = routingFixtureTime(f)
		common := change.RouteReference{Version: 1, ContextID: source.ContextID, RouterID: source.RouterID, BaseContextID: source.ContextID, BaseRouterID: source.RouterID,
			ViewID: view.ID, Generation: view.Generation, Sequence: "9007199254740993", BatchDigest: strings.Repeat("a", 64), ObservedAt: source.ObservedAt,
			View: routingViewFixture().Kind, Action: "announcement", AFI: 1, SAFI: 1, HasPathID: true}
		original := routingChangeSource{Version: 1, Source: source, ViewBornAt: born, ViewID: view.ID, Generation: view.Generation, Sequence: common.Sequence, BatchDigest: common.BatchDigest, View: common.View, AFI: 1, SAFI: 1}
		private, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		type row struct {
			ID      string                `json:"id"`
			Prefix  string                `json:"prefix"`
			Routing change.RouteReference `json:"routing"`
		}
		inputs := make([]row, 0, population)
		for index := 0; index < population; index++ {
			id, err := crypto.UUIDv4()
			if err != nil {
				t.Fatal(err)
			}
			reference := common
			reference.PathID = uint32(index)
			prefix := fmt.Sprintf("198.%d.%d.%d/32", (index>>16)&255, (index>>8)&255, index&255)
			inputs = append(inputs, row{id, prefix, reference})
			byTenant[tenant] = append(byTenant[tenant], change.Event{ID: id, TenantID: tenant, Source: ownedRoutingChangeSource, Kind: change.KindRoute, Target: source.RouterID, Prefix: prefix, OccurredAt: source.ObservedAt, Routing: &reference})
		}
		body, err := json.Marshal(inputs)
		if err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO change_events(id,tenant_id,source,kind,title,target,prefix,occurred_at,routing,routing_source)
 SELECT input.id,$1,$2,'route','Modeled original route announcement',$3,input.prefix,$4,input.routing,$6::jsonb
 FROM jsonb_to_recordset($5::jsonb) AS input(id uuid,prefix text,routing jsonb)`, tenant, ownedRoutingChangeSource, source.RouterID, source.ObservedAt, body, private)
			return err
		})
	}
	verify := func(tenant string, events []change.Event, memory int64, publication RoutingChangeAuthorizer) error {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		return tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			return (ChangeEvents{}).VerifyRoutingChangeReferencesInScope(ctx, sc, events, memory, publication)
		})
	}
	for _, tenant := range f.tenants {
		calls := 0
		authorize := func(ctx context.Context, _ tenancy.Scope, source BGPRoutingSource, event change.Event) error {
			calls++
			if source.TenantID != tenant || event.TenantID != tenant || source.ContextID != f.contextID || event.Routing.Sequence != "9007199254740993" {
				t.Fatal("reader adopted a foreign source or rounded an original sequence")
			}
			return ctx.Err()
		}
		if err := verify(tenant, byTenant[tenant], 64<<20, authorize); err != nil || calls != population {
			t.Fatal("complete source batch was clipped or unavailable", calls, err)
		}
		calls = 0
		if err := verify(tenant, byTenant[tenant], 4096, authorize); err == nil || calls != 0 {
			t.Fatal("unadmitted source prefix reached publication", calls, err)
		}
		if err := verify(tenant, byTenant[tenant][:1], 64<<20, nil); err == nil {
			t.Fatal("source metadata substituted for current user authorization")
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	forged := byTenant[b][0]
	forged.TenantID = a
	foreignCalls := 0
	if err := verify(a, []change.Event{forged}, 64<<20, func(context.Context, tenancy.Scope, BGPRoutingSource, change.Event) error { foreignCalls++; return nil }); err == nil || foreignCalls != 0 {
		t.Fatal("foreign stored source crossed FORCE-RLS", err)
	}
	forged = byTenant[a][0]
	reference := *forged.Routing
	reference.Sequence = "9007199254740994"
	forged.Routing = &reference
	if err := verify(a, []change.Event{forged}, 64<<20, func(context.Context, tenancy.Scope, BGPRoutingSource, change.Event) error { return nil }); err == nil {
		t.Fatal("changed reference borrowed an original source")
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id='role-listener' AND source_kind='bmp_peer' AND source_ref='role-router'`, a)
		return err
	})
	current := func(ctx context.Context, _ tenancy.Scope, _ BGPRoutingSource, _ change.Event) error { return ctx.Err() }
	if err := verify(a, byTenant[a][:1], 64<<20, current); err == nil {
		t.Fatal("removed origin source kept historical route metadata readable")
	}
	if err := verify(b, byTenant[b], 64<<20, current); err != nil {
		t.Fatal("one tenant's source removal changed its sibling", err)
	}
}
