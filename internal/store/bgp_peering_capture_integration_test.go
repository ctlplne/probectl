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
	"testing"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestPeeringCaptureReaderKeepsCurrentTargetTenantAndOriginalSourceAuthority(t *testing.T) {
	f, changes, _, input := newRoutingFlowCaptureFixture(t)
	service := NewBGPRoutingFlowCaptures(f.pool)
	raw := routingCaptureHash([]byte("paired original peering routing observation"))
	var refs [2]BGPRoutingCaptureReference
	var targets [2]BGPPeeringCaptureTarget
	var references [2]flowstore.RoutingCaptureRead
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		var err error
		refs[lane], err = service.CaptureAuthenticated(ctx, "routing-flow", raw, input, routingViewBudget())
		if err != nil || refs[lane].Key == ([32]byte{}) {
			t.Fatal("peering source fixture did not retain its original routing evidence", err)
		}
	}
	read := func(lane int, references []flowstore.RoutingCaptureRead, target BGPPeeringCaptureTarget, budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error) ([]flowstore.RoutingProjection, error) {
		t.Helper()
		var out []flowstore.RoutingProjection
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (BGPRouting{}).FlowPeeringCaptureProjectionsInScope(ctx, sc, references, target, budget, authorize)
			return err
		})
		return out, err
	}
	for lane, tenant := range f.tenants {
		peer := changes[lane].Segments[1].Values[0]
		target := BGPPeeringCaptureTarget{Scope: entity.Scope{TenantID: tenant, ContextID: f.contextID}, RouterID: f.routerID, PeerASN: peer}
		reference := flowstore.RoutingCaptureRead{Sender: "routing-flow", Witness: entity.FlowCaptureWitness{RawDigest: raw, Input: input}, Ref: refs[lane]}
		targets[lane], references[lane] = target, reference
		calls := 0
		authorize := func(_ context.Context, record entity.ContextRecord) error {
			calls++
			if record.TenantID != target.TenantID || record.ContextID != target.ContextID {
				t.Fatal("peering reader authorized another tenant or context")
			}
			return nil
		}
		got, err := read(lane, []flowstore.RoutingCaptureRead{reference}, target, routingViewBudget(), authorize)
		if err != nil || len(got) != 1 || calls != 1 || got[0].Peering == nil || got[0].Peering.Source != bgp.PeeringPathEligible || got[0].Scope != target.Scope || got[0].Key != refs[lane].Key || got[0].Clock != refs[lane].CapturedAt.UnixNano() {
			t.Fatal("peering reader lost current owned target, complete original match or clock", got, err)
		}
		denied := errors.New("current peering context permission removed")
		if got, err = read(lane, nil, target, BGPRoutingBudget{}, func(context.Context, entity.ContextRecord) error { return denied }); !errors.Is(err, denied) || got != nil {
			t.Fatal("empty peering selection or tiny budget bypassed current context authority", err)
		}
		foreign := target
		foreign.TenantID = f.tenants[1-lane]
		if got, err = read(lane, nil, foreign, routingViewBudget(), authorize); !errors.Is(err, entity.ErrScopeMismatch) || got != nil {
			t.Fatal("peering reader crossed the tenant boundary before availability", err)
		}
		foreign = target
		foreign.RouterID = "88888888-8888-4888-8888-888888888888"
		if got, err = read(lane, []flowstore.RoutingCaptureRead{reference}, foreign, routingViewBudget(), authorize); err != nil || len(got) != 0 {
			t.Fatal("peering reader selected captures from another canonical router", got, err)
		}
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id='routing-flow' AND source_kind='flow_exporter'`, f.tenants[0])
		return err
	})
	for lane, tenant := range f.tenants {
		got, err := read(lane, []flowstore.RoutingCaptureRead{references[lane]}, targets[lane], routingViewBudget(), func(_ context.Context, record entity.ContextRecord) error {
			if record.TenantID != tenant || record.ContextID != f.contextID {
				t.Fatal("retired peering read reached another tenant/context")
			}
			return nil
		})
		want := 1
		if lane == 0 {
			want = 0
		}
		if err != nil || len(got) != want {
			t.Fatal("peering reader reused revoked original source authority or damaged its sibling", got, err)
		}
	}
}
