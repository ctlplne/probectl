// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	gouuid "github.com/google/uuid"
)

func TestIncidentConfiguredTestsKeepExplicitCurrentTenantBindings(t *testing.T) {
	f, _, graphs := seedDependencyGraphFixture(t)
	inputs := func(lane int) *store.IncidentImpactInputs {
		node := graphs[f.tenants[lane]].Nodes[0]
		return &store.IncidentImpactInputs{TenantID: f.tenants[lane], Entities: []store.IncidentImpactEntity{{ContextID: f.contextID, EntityID: node.EntityID, IncidentRoot: true}}}
	}
	read := func(lane int, input *store.IncidentImpactInputs, budget int64, deny bool) ([]store.IncidentConfiguredTest, error) {
		t.Helper()
		tenant := f.tenants[lane]
		var out []store.IncidentConfiguredTest
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var generation int64
			err := sc.Q.QueryRow(ctx, `SELECT COALESCE((SELECT generation FROM flow_snapshot_epochs WHERE tenant_id=$1),1)`, tenant).Scan(&generation)
			if err != nil {
				return err
			}
			inputCopy := *input
			inputCopy.SourceGeneration = generation
			out, err = (store.Incidents{}).ConfiguredImpactTestsInScope(ctx, sc, &inputCopy, budget, func(_ context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, testID string) error {
				if record.TenantID != tenant || member.ContextID != f.contextID || member.EntityID != graphs[tenant].Nodes[0].EntityID {
					t.Fatal("foreign canonical configuration reached the reader policy")
				}
				if deny && testID != "" {
					return apierror.Forbidden("test resource denied")
				}
				return nil
			})
			return err
		})
		return out, err
	}
	for lane, tenant := range f.tenants {
		node := graphs[tenant].Nodes[0]
		out, err := read(lane, inputs(lane), 1<<20, false)
		if err != nil || len(out) != 1 || out[0].TestID != node.TestID || out[0].AgentID != node.AgentID || out[0].EntityID != node.EntityID || out[0].ContextID != f.contextID || out[0].CurrentSince.IsZero() {
			t.Fatal("complete explicit current configured-test membership was lost", out, err)
		}
		if out, err := read(lane, inputs(1-lane), 1<<20, false); !errors.Is(err, entity.ErrScopeMismatch) || out != nil {
			t.Fatal("foreign incident tenant borrowed this configuration scope", out, err)
		}
		if out, err := read(lane, inputs(lane), 1<<20, true); err == nil || out != nil {
			t.Fatal("denied test policy returned a configuration prefix", out, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE tests SET target='198.51.100.99' WHERE tenant_id=$1 AND id=$2`, tenant, node.TestID)
			return err
		})
		if out, err := read(lane, inputs(lane), 1<<20, false); err != nil || len(out) != 0 {
			t.Fatal("changed destination reused an old canonical path binding", out, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE tests SET target='192.0.2.1' WHERE tenant_id=$1 AND id=$2`, tenant, node.TestID)
			return err
		})
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			registry := store.NewEntityRegistry(f.pool)
			for range 9 {
				id := gouuid.NewString()
				if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled) VALUES($1,$2,'explicit configured member','icmp','192.0.2.1',30,2,'{}',true)`, tenant, id); err != nil {
					return err
				}
				if err := registry.AssignPathTestContext(ctx, sc, id, f.contextID); err != nil {
					return err
				}
				if err := registry.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: node.AgentID, Kind: entity.PathAgent, SourceRef: id}, f.contextID, node.EntityID); err != nil {
					return err
				}
			}
			return nil
		})
		if out, err := read(lane, inputs(lane), 1<<20, false); err != nil || len(out) != 10 {
			t.Fatal("configured-test reader hid an enabled owned member", len(out), err)
		}
		if out, err := read(lane, inputs(lane), 4096, false); !errors.Is(err, store.ErrIncidentImpactBudget) || out != nil {
			t.Fatal("configured-test memory refusal returned a usable prefix", out, err)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND context_id=$2 AND source_kind='path_agent' AND anchor_entity_id=$3`, a, f.contextID, graphs[a].Nodes[0].EntityID)
		return err
	})
	if out, err := read(0, inputs(0), 1<<20, false); err != nil || len(out) != 0 {
		t.Fatal("withdrawn canonical assignment remained visible", out, err)
	}
	if out, err := read(1, inputs(1), 1<<20, false); err != nil || len(out) != 10 || out[0].ContextID != f.contextID {
		t.Fatal("source withdrawal changed sibling tenant configuration", len(out), b, err)
	}
	t.Log("real-integration: current explicit configured-test membership and whole-population refusals in paired app-role PG/RLS; configuration is modeled and proves no measured incident effect or historical test outcome")
}
