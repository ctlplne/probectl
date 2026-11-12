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

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestCapturedFlowOwnersKeepOriginalIdentityAcrossRefreshAndRefuseReassignment(t *testing.T) {
	f, _, serials, input := newRoutingFlowCaptureFixture(t)
	service := NewBGPRoutingFlowCaptures(f.pool)
	raw := routingCaptureHash([]byte("captured identity metadata fixture"))
	refs := make([]flowstore.RoutingCaptureRead, len(f.tenants))
	for lane, tenant := range f.tenants {
		ref, err := service.CaptureAuthenticated(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), "routing-flow", raw, input, routingViewBudget())
		if err != nil {
			t.Fatal(err)
		}
		refs[lane] = flowstore.RoutingCaptureRead{Sender: "routing-flow", Witness: entity.FlowCaptureWitness{RawDigest: raw, Input: input}, Ref: ref}
	}
	read := func(lane int, selected []flowstore.RoutingCaptureRead, authorize func(context.Context, entity.ContextRecord, InterfaceRoleFlowBinding) error) ([]CapturedFlowOwner, error) {
		t.Helper()
		var out []CapturedFlowOwner
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (CapturedFlowOwners{}).ReadInScope(ctx, sc, selected, routingViewBudget(), authorize)
			return err
		})
		return out, err
	}
	for lane, tenant := range f.tenants {
		calls := 0
		allow := func(_ context.Context, record entity.ContextRecord, source InterfaceRoleFlowBinding) error {
			calls++
			if record.TenantID != tenant || record.ContextID != f.contextID || source.TenantID != tenant ||
				source.ContextID != f.contextID || source.RouterID != f.routerID || source.AgentID != "routing-flow" ||
				source.Exporter != input.Exporter || source.Protocol != input.Protocol || source.Domain != input.Domain {
				t.Fatal("flow owner authorization received a foreign or incomplete source selector")
			}
			return nil
		}
		initial, err := read(lane, []flowstore.RoutingCaptureRead{refs[lane]}, allow)
		if err != nil || len(initial) != 1 || !initial[0].Available || initial[0].Owner.TenantID != tenant || initial[0].Owner.SourceID == "" || initial[0].CurrentSourceID != initial[0].Owner.SourceID || calls != 1 {
			t.Fatal("owned captured measurement point was unavailable or mis-scoped", initial, calls, err)
		}
		original := initial[0]
		routingFlowFixtureEvidence(t, f, tenant, "routing-flow", serials[lane], input.Exporter.String())
		refreshed, err := read(lane, []flowstore.RoutingCaptureRead{refs[lane]}, allow)
		if err != nil || len(refreshed) != 1 || !refreshed[0].Available || refreshed[0].Reference != original.Reference ||
			refreshed[0].Owner.SourceID != original.Owner.SourceID || refreshed[0].CurrentSourceID == original.CurrentSourceID {
			t.Fatal("refresh replaced original flow identity or erased a continuous baseline", refreshed, err)
		}
		denied := errors.New("current flow source denied")
		if out, err := read(lane, []flowstore.RoutingCaptureRead{refs[lane]}, func(context.Context, entity.ContextRecord, InterfaceRoleFlowBinding) error { return denied }); !errors.Is(err, denied) || out != nil {
			t.Fatal("captured flow owner bypassed current source authorization", out, err)
		}
		for _, changed := range []flowstore.RoutingCaptureRead{refs[1-lane], refs[lane]} {
			if changed == refs[lane] {
				changed.Witness.RawDigest[0] ^= 1
			}
			if out, err := read(lane, []flowstore.RoutingCaptureRead{changed}, allow); err == nil || out != nil {
				t.Fatal("foreign or forged original flow reference supplied identity", out, err)
			}
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET assigned_at=clock_timestamp()
				WHERE tenant_id=$1 AND context_id=$2 AND agent_id='routing-flow'
				AND source_kind='flow_exporter' AND source_ref=$3`, tenant, f.contextID, input.Exporter.String())
			return err
		})
		routingFlowFixtureEvidence(t, f, tenant, "routing-flow", serials[lane], input.Exporter.String())
		after, err := read(lane, []flowstore.RoutingCaptureRead{refs[lane]}, allow)
		if err != nil || len(after) != 1 || after[0].Available || after[0].Owner.SourceID != "" || after[0].CurrentSourceID != "" {
			t.Fatal("a recreated source association revived an old flow identity", after, err)
		}
		peer, err := read(1-lane, []flowstore.RoutingCaptureRead{refs[1-lane]}, func(context.Context, entity.ContextRecord, InterfaceRoleFlowBinding) error { return nil })
		// The first lane's reassignment must not affect its sibling. By the
		// second iteration the first lane is already deliberately unavailable.
		if err != nil || len(peer) != 1 || peer[0].Available != (lane == 0) {
			t.Fatal("flow ownership transition crossed tenant storage", peer, err)
		}
	}
	t.Log("real-integration: existing authenticated capture service/immutable objects and current ownership under paired app-role PG/RLS; observations are modeled, incident traffic/customer and real-flow proof remain separate")
}
