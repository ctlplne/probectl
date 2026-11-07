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

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual application-role TLS Postgres/FORCE-RLS; policy callbacks and source
// identities are modeled. Public API and authenticated sender proof are separate.
func TestRoutingOperatorConfigurationKeepsTenantPolicyCASAndAtomicAudit(t *testing.T) {
	f := newRoleInputsFixture(t)
	targetContext, targetRouter := uuid.NewString(), uuid.NewString()
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'target','routed')`, tenant, targetContext); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','owned-router')`, tenant, targetContext, targetRouter)
			return err
		})
	}
	bindings := []BGPRoutingBinding{{ContextID: targetContext, RouterID: targetRouter, Distinguisher: "ffffffffffffffff", BGPIdentifier: "0.0.0.0", Families: []uint16{1, 2}, SourceFormat: BGPRoutingSourceFRRLocRIBV1}}
	denied, auditFailure := errors.New("policy denied"), errors.New("audit append refused")
	authorizer := func(lane int, deny string) RoutingContextAuthorizer {
		return func(_ context.Context, record entity.ContextRecord) error {
			if record.TenantID != f.tenants[lane] || record.ContextID == "" || record.SiteID == "" || record.VRFID == "" {
				t.Fatal("routing policy received foreign or invented context attributes", record)
			}
			if record.ContextID == deny {
				return denied
			}
			return nil
		}
	}
	put := func(lane int, epoch string, next []BGPRoutingBinding, deny string, rollback bool) (BGPRoutingBindingConfiguration, error) {
		source := routingFixtureSource(f, lane)
		var out BGPRoutingBindingConfiguration
		err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (BGPRouting{}).ReplaceBindingsInScope(ctx, sc, source.CollectorAgentID, source.SourceRef, source.ContextID, epoch, next, routingViewBudget(), authorizer(lane, deny))
			if err == nil && rollback {
				return auditFailure
			}
			return err
		})
		return out, err
	}
	read := func(lane int, deny string) (BGPRoutingBindingConfiguration, error) {
		source := routingFixtureSource(f, lane)
		var out BGPRoutingBindingConfiguration
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (BGPRouting{}).BindingsInScope(ctx, sc, source.CollectorAgentID, source.SourceRef, routingViewBudget(), authorizer(lane, deny))
			return err
		})
		return out, err
	}
	if out, err := read(0, f.contextID); !errors.Is(err, denied) || out.CollectorAgentID != "" {
		t.Fatal("routing configuration disclosed a denied base context", out, err)
	}
	if _, err := put(0, "", bindings, targetContext, false); !errors.Is(err, denied) {
		t.Fatal("routing replacement bypassed proposed target authorization", err)
	}
	if out, err := read(0, ""); err != nil || out.Manifest != nil {
		t.Fatal("refused routing configuration changed the legacy source", out, err)
	}
	first := make([]BGPRoutingBindingConfiguration, 2)
	for lane := range f.tenants {
		out, err := put(lane, "", bindings, "", false)
		if err != nil || out.Manifest == nil || len(out.Manifest.Bindings) != 1 || out.Manifest.Bindings[0].SourceFormat != BGPRoutingSourceFRRLocRIBV1 {
			t.Fatal("owned routing operator configuration was refused", out, err)
		}
		first[lane] = out
	}
	if first[0].Manifest.Epoch == first[1].Manifest.Epoch {
		t.Fatal("paired tenants shared one routing configuration incarnation")
	}
	if out, err := read(0, targetContext); !errors.Is(err, denied) || out.CollectorAgentID != "" {
		t.Fatal("routing configuration disclosed a denied current target", out, err)
	}
	if _, err := put(0, first[0].Manifest.Epoch, nil, targetContext, false); !errors.Is(err, denied) {
		t.Fatal("routing withdrawal bypassed current target authorization", err)
	}
	if _, err := put(0, first[0].Manifest.Epoch, bindings, "", true); !errors.Is(err, auditFailure) {
		t.Fatal("routing audit failure did not abort its write", err)
	}
	for lane := range f.tenants {
		out, err := read(lane, "")
		if err != nil || out.Manifest == nil || out.Manifest.Epoch != first[lane].Manifest.Epoch {
			t.Fatal("refused or rolled-back routing write changed a tenant configuration", out, err)
		}
	}
	empty, err := put(0, first[0].Manifest.Epoch, nil, "", false)
	if err != nil || empty.Manifest == nil || empty.Manifest.Epoch == first[0].Manifest.Epoch || len(empty.Manifest.Bindings) != 0 {
		t.Fatal("explicit withdrawal restored a legacy routing fallback", empty, err)
	}
	if _, err := put(0, first[0].Manifest.Epoch, bindings, "", false); !errors.Is(err, ErrBGPRoutingBindingConflict) {
		t.Fatal("stale routing configuration overwrote its replacement epoch", err)
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		foreign := routingFixtureSource(f, 1)
		if out, err := (BGPRouting{}).BindingsInScope(ctx, sc, foreign.CollectorAgentID, foreign.SourceRef, routingViewBudget(), authorizer(0, "")); err == nil || out.CollectorAgentID != "" {
			t.Fatal("foreign source configuration escaped tenant storage isolation", out, err)
		}
		return nil
	})
	f.in(f.tenants[1], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_contexts WHERE tenant_id=$1 AND id=$2`, f.tenants[1], targetContext)
		return err
	})
	if out, err := read(1, ""); err == nil || out.CollectorAgentID != "" {
		t.Fatal("routing readback invented policy attributes for a deleted context", out, err)
	}
	if out, err := put(1, first[1].Manifest.Epoch, nil, "", false); err != nil || out.Manifest == nil || len(out.Manifest.Bindings) != 0 {
		t.Fatal("authorized base owner could not withdraw a deleted routing target", out, err)
	}
}
