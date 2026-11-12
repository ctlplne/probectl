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
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentImpactSourcesKeepCurrentDeviceInterfaceAndTenantAuthority(t *testing.T) {
	f, _, _, _ := newRoutingFlowCaptureFixture(t)
	read := func(lane int, override *IncidentImpactInputs, authorize func(context.Context, entity.ContextRecord, IncidentImpactEntity) error) ([]IncidentImpactSource, error) {
		t.Helper()
		tenant := f.tenants[lane]
		input := &IncidentImpactInputs{TenantID: tenant, Entities: []IncidentImpactEntity{
			{ContextID: f.contextID, EntityID: f.routerID, IncidentRoot: true, SignalIDs: []string{}},
			{ContextID: f.contextID, EntityID: f.interfaceID, SignalIDs: []string{}},
		}}
		if override != nil {
			input = override
		}
		var out []IncidentImpactSource
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (Incidents{}).ImpactSourcesInScope(ctx, sc, input, roleInputsBudget(), authorize)
			return err
		})
		return out, err
	}
	allow := func(context.Context, entity.ContextRecord, IncidentImpactEntity) error { return nil }
	for lane, tenant := range f.tenants {
		calls := 0
		out, err := read(lane, nil, func(_ context.Context, record entity.ContextRecord, member IncidentImpactEntity) error {
			calls++
			if record.TenantID != tenant || record.ContextID != f.contextID || member.ContextID != record.ContextID {
				t.Fatal("impact source authorization received a foreign context")
			}
			return nil
		})
		if err != nil || len(out) != 2 || calls != 2 {
			t.Fatal("complete incident source membership was unavailable", len(out), calls, err)
		}
		for i, source := range out {
			if source.Reason != "current_attested_source" || len(source.Selections) != 1 || len(source.Evidence) == 0 || source.ValidUntil.IsZero() {
				t.Fatal("owned source lost its complete current evidence", source)
			}
			selection := source.Selections[0]
			if selection.AgentID != "routing-flow" || selection.Domain != ^uint32(0) || selection.Exporter.String() != "192.0.2.1" || selection.Protocol != "ipfix" || selection.WholeDevice != (i == 0) || (i == 1 && (len(selection.InterfaceIndices) != 1 || selection.InterfaceIndices[0] != 7)) {
				t.Fatal("incident source used a raw label or crossed its canonical interface", source)
			}
		}
		denied := errors.New("current incident context denied")
		if leaked, err := read(lane, nil, func(context.Context, entity.ContextRecord, IncidentImpactEntity) error { return denied }); !errors.Is(err, denied) || leaked != nil {
			t.Fatal("denied incident source disclosed a usable prefix", leaked, err)
		}
		if leaked, err := read(lane, &IncidentImpactInputs{TenantID: f.tenants[1-lane]}, allow); err == nil || leaked != nil {
			t.Fatal("incident membership replaced storage tenant", leaked, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,'unobserved-impact-competitor',$2)`, tenant, f.contextID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,'unobserved-impact-competitor','flow_exporter','192.0.2.1',$2,$3)`, tenant, f.contextID, f.otherRouter)
			return err
		})
		withdrawn, err := read(lane, nil, allow)
		if err != nil || len(withdrawn) != 2 || len(withdrawn[0].Selections) != 0 || len(withdrawn[1].Selections) != 0 {
			t.Fatal("unobserved competing ownership was pruned to manufacture authority", withdrawn, err)
		}
		peer, err := read(1-lane, nil, allow)
		if err != nil || len(peer) != 2 || (len(peer[0].Selections) == 1) != (lane == 0) {
			t.Fatal("impact source withdrawal crossed tenant storage", peer, err)
		}
	}
	t.Log("real-integration: paired app-role PostgreSQL/RLS current source selection; sender observations are modeled, served/native and physical-flow qualification remain separate")
}
