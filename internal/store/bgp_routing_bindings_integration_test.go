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
	"testing"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real application-role Postgres/FORCE-RLS; operator and source identities are
// modeled. These private storage components do not activate non-global ingest.
func TestRoutingBindingManifestKeepsTenantEpochTargetsAndWholeAdmission(t *testing.T) {
	f := newRoleInputsFixture(t)
	targetContext, targetRouter := uuid.NewString(), uuid.NewString()
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same-site','routed-vrf')`, tenant, targetContext, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','same-router')`, tenant, targetContext, targetRouter)
			return err
		})
	}
	inputs := []routingSourceBinding{
		{ContextID: f.contextID, RouterID: f.routerID, Distinguisher: "0000000000000000", BGPIdentifier: "192.0.2.1", Families: []uint16{1, 2}},
		{ContextID: targetContext, RouterID: targetRouter, Distinguisher: "ffffffffffffffff", BGPIdentifier: "0.0.0.0", Families: []uint16{2, 1}},
	}
	put := func(lane int, epoch string, bindings []routingSourceBinding, budget BGPRoutingBudget) (routingSourceManifest, error) {
		source := routingFixtureSource(f, lane)
		var manifest routingSourceManifest
		err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			manifest, err = putRoutingBindings(ctx, sc, source.CollectorAgentID, source.SourceRef, source.ContextID, epoch, bindings, budget)
			return err
		})
		return manifest, err
	}
	read := func(lane int) routingSourceManifest {
		var manifest routingSourceManifest
		var raw []byte
		source := routingFixtureSource(f, lane)
		f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			var base string
			if err := sc.Q.QueryRow(ctx, `SELECT context_id::text,routing_epoch::text,routing_bindings FROM entity_source_contexts
 WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='bmp_peer' AND source_ref=$3`, source.TenantID, source.CollectorAgentID, source.SourceRef).Scan(&base, &manifest.Epoch, &raw); err != nil {
				return err
			}
			if base != f.contextID {
				t.Fatal("routing assignment silently changed another evidence plane context")
			}
			return nil
		})
		if err := json.Unmarshal(raw, &manifest.Bindings); err != nil {
			t.Fatal(err)
		}
		return manifest
	}
	first, err := put(0, "", inputs, routingViewBudget())
	if err != nil || first.AssignedAt.IsZero() || first.Epoch == "" || len(first.Bindings) != 2 || read(0).Epoch != first.Epoch {
		t.Fatal("complete explicit source binding was not retained", err)
	}
	second, err := put(1, "", inputs, routingViewBudget())
	if err != nil || second.Epoch == first.Epoch || second.Bindings[0].ID == first.Bindings[0].ID {
		t.Fatal("paired source selector borrowed a foreign incarnation", err)
	}
	if _, err := put(0, "", inputs, routingViewBudget()); !errors.Is(err, errRoutingBindingConflict) || read(0).Epoch != first.Epoch {
		t.Fatal("stale routing editor replaced a current binding", err)
	}
	foreignRouter := uuid.NewString()
	f.in(f.tenants[1], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','foreign-only')`, f.tenants[1], targetContext, foreignRouter)
		return err
	})
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entities WHERE context_id=$1 AND id=$2`, targetContext, foreignRouter).Scan(&count)
		if err == nil && count != 0 {
			t.Fatal("routing target escaped storage-layer tenant RLS")
		}
		return err
	})
	foreign := append([]routingSourceBinding(nil), inputs...)
	foreign[1].RouterID = foreignRouter
	if _, err := put(0, first.Epoch, foreign, routingViewBudget()); err == nil || read(0).Epoch != first.Epoch || read(1).Epoch != second.Epoch {
		t.Fatal("foreign target acquired an operator routing assignment", err)
	}
	budget := routingViewBudget()
	budget.StateBytes = 1
	if _, err := put(0, first.Epoch, inputs, budget); !errors.Is(err, ErrBGPRoutingBudget) || read(0).Epoch != first.Epoch {
		t.Fatal("unadmitted routing metadata replaced current complete bindings", err)
	}
	empty, err := put(0, first.Epoch, nil, routingViewBudget())
	if err != nil || empty.Epoch == first.Epoch || len(read(0).Bindings) != 0 || read(1).Epoch != second.Epoch {
		t.Fatal("explicit empty routing manifest revived legacy or foreign sources", err)
	}
	if _, err := put(0, first.Epoch, inputs, routingViewBudget()); !errors.Is(err, errRoutingBindingConflict) {
		t.Fatal("old routing epoch revived withdrawn bindings", err)
	}
}
