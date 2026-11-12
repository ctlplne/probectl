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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentImpactInputsKeepCompleteCitationsAndTenantScope(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	var tenants []string
	for lane := range 2 {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("impact-inputs-%d-%d", time.Now().UnixNano(), lane), "impact inputs")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	contextID := uuid.NewString()
	entities := make([]string, 701)
	for i := range entities {
		entities[i] = uuid.NewString()
	}
	type signalRow struct{ ID, Entity string }
	type fixture struct {
		incident, unresolved string
		signals              map[string][]string
	}
	fixtures := map[string]fixture{}
	for _, tenant := range tenants {
		f := fixture{incident: uuid.NewString(), unresolved: uuid.NewString(), signals: map[string][]string{}}
		rows := make([]signalRow, 0, len(entities)+1)
		for _, id := range append(append([]string{}, entities...), entities[0]) {
			signalID := uuid.NewString()
			rows = append(rows, signalRow{ID: signalID, Entity: id})
			f.signals[id] = append(f.signals[id], signalID)
		}
		body, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'impact site','impact VRF')`,
				tenant, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label)
				SELECT $1,$2,id,'device','owned impact entity' FROM unnest($3::uuid[]) id`, tenant, contextID, entities); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents
				(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted,signal_count)
				VALUES($1,$2,'complete impact',$3,$4,true,$5)`, tenant, f.incident, contextID, entities[0], len(rows)+1); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incident_signals
				(tenant_id,incident_id,id,plane,kind,severity,title,occurred_at,entity_context_id,entity_id,identity_lookup_attempted)
				SELECT $1,$2,r."ID",'network','alert.firing','warning','retained source',now(),$3,r."Entity",true
				FROM jsonb_to_recordset($4::jsonb) AS r("ID" uuid,"Entity" uuid)`, tenant, f.incident, contextID, body); err != nil {
				return err
			}
			// A plausible identity in payload attributes remains an unproved claim.
			_, err := sc.Q.Exec(ctx, `INSERT INTO incident_signals
				(tenant_id,incident_id,id,plane,kind,severity,title,occurred_at,attributes)
				VALUES($1,$2,$3,'network','claimed.identity','warning','unresolved',now(),
				jsonb_build_object('entity_id',$4::text,'context_id',$5::text))`, tenant, f.incident, f.unresolved, uuid.NewString(), contextID)
			return err
		})
		fixtures[tenant] = f
	}
	for lane, tenant := range tenants {
		f := fixtures[tenant]
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			out, err := (Incidents{}).ImpactInputs(ctx, sc, f.incident, 2<<20)
			if err != nil || out == nil || out.TenantID != tenant || out.IncidentID != f.incident || out.RootUnresolved || len(out.Entities) != len(entities) || len(out.UnresolvedSignalIDs) != 1 || out.UnresolvedSignalIDs[0] != f.unresolved {
				t.Fatal("complete impact input was shortened, mis-scoped or trusted attributes", out, err)
			}
			for _, ref := range out.Entities {
				want := f.signals[ref.EntityID]
				if ref.ContextID != contextID || len(want) == 0 || len(ref.SignalIDs) != len(want) || ref.IncidentRoot != (ref.EntityID == entities[0]) {
					t.Fatal("canonical impact reference lost its exact owned citations", ref)
				}
				for _, id := range ref.SignalIDs {
					found := false
					for _, expected := range want {
						found = found || id == expected
					}
					if !found {
						t.Fatal("impact reference borrowed a sibling signal citation")
					}
				}
			}
			foreign := fixtures[tenants[1-lane]]
			if leaked, err := (Incidents{}).ImpactInputs(ctx, sc, foreign.incident, 2<<20); err == nil || leaked != nil {
				t.Fatal("foreign incident input escaped its storage scope")
			}
			other := tenancy.WithTenant(ctx, tenancy.ID(tenants[1-lane]))
			if leaked, err := (Incidents{}).ImpactInputs(other, sc, f.incident, 2<<20); !errors.Is(err, entity.ErrScopeMismatch) || leaked != nil {
				t.Fatal("contradictory context borrowed an existing tenant scope", err)
			}
			if prefix, err := (Incidents{}).ImpactInputs(ctx, sc, f.incident, 64<<10); !errors.Is(err, ErrIncidentImpactBudget) || prefix != nil {
				t.Fatal("memory refusal returned a usable impact prefix", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Log("real-integration: complete incident membership/citations and refusals in both app-role PG/RLS tenants; incident rows are modeled, traffic/customer/served proof remains separate")
}
