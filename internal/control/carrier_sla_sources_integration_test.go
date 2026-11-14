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
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Agent/test setup is modeled. Application-role PostgreSQL, composite source
// FKs, FORCE-RLS, revision immutability and source-retirement cascades are real.
func TestCarrierSLASourceReferencesKeepTenantIdentityAndRetireWithoutLosingTerms(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	repository := flow.NewPostgresCapacityAgreements(f.pool, 1<<30, 8<<20, 8<<20, audit.TenantRecord)
	sources := map[string]flow.CarrierSLASource{}
	definitions := map[string]flow.CapacityAgreementDefinition{}
	records := map[string]flow.CapacityAgreement{}
	for _, tenant := range f.tenants {
		agent, testID := gouuid.NewString(), gouuid.NewString()
		sources[tenant] = flow.CarrierSLASource{AgentID: agent, TestID: testID}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, agent, "circuit probe", "127.0.0.1", "fixture", crypto.AgentSPIFFEID(tenant, agent), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled)
                VALUES($1,$2,'circuit probe','icmp','198.51.100.10',10,1,'{"count":"3","allow_private_targets":"true"}'::jsonb,true)`, tenant, testID); err != nil {
				return err
			}
			registry := store.NewEntityRegistry(f.pool)
			if err := registry.AssignPathTestContext(ctx, sc, testID, f.contextID); err != nil {
				return err
			}
			return registry.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agent, Kind: entity.PathAgent, SourceRef: testID}, f.contextID, f.routerID)
		})
		definition := flow.CapacityAgreementDefinition{Name: "Circuit", Reference: "operator terms", ValidFrom: "2026-11-01T00:00:00Z", Target: flow.CapacityTarget{Kind: "interface", ContextID: f.contextID, InterfaceID: f.interfaceID}, BillingDay: 1, Timezone: "UTC", Direction: "in", Currency: "USD", CommitBPS: "0", UnitBPS: "1", UnitPrice: "0",
			SLA: &flow.CarrierSLATerms{Carrier: "operator carrier", CircuitID: "same circuit", Currency: "USD", MonthlyCharge: "100.125", CreditCapRatio: "1.25", Aggregation: "maximum", Sources: []flow.CarrierSLASource{{AgentID: agent, TestID: testID}}, Rules: []flow.CarrierSLARule{{ID: "loss", Metric: "loss", Basis: "original_packet_ratio", GoodWhen: "at_most", Threshold: "0.01", CreditBands: []flow.CarrierSLACreditBand{{From: "0.01", CreditRatio: "0.1"}}}}}}
		definitions[tenant] = definition
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		record, err := repository.SaveCapacityAgreement(ctx, f.users[tenant], flow.SaveCapacityAgreement{Definition: definition})
		if err != nil {
			t.Fatal("explicit owned source was refused", err)
		}
		if !record.SLASourceMetadataTrusted {
			t.Fatal("current tenant source lost its canonical metadata proof")
		}
		records[tenant] = record
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var contextID, deviceID, user string
			err := sc.Q.QueryRow(ctx, `SELECT context_id::text,device_id::text,current_user FROM flow_capacity_agreement_sla_refs WHERE tenant_id=$1 AND agreement_id=$2 AND version=1 AND agent_id=$3 AND test_id=$4`, tenant, record.ID, agent, testID).Scan(&contextID, &deviceID, &user)
			if err == nil && (contextID != f.contextID || deviceID != f.routerID || user != tenancy.AppRole) {
				t.Fatal("source canonical scope or least-privilege role changed")
			}
			return err
		})
	}
	a, b := f.tenants[0], f.tenants[1]
	revised := definitions[b]
	terms := *revised.SLA
	terms.Sources = nil
	revised.SLA = &terms
	if _, err := repository.SaveCapacityAgreement(tenancy.WithTenant(t.Context(), tenancy.ID(b)), f.users[b], flow.SaveCapacityAgreement{ID: records[b].ID, Version: "1", Definition: revised}); err != nil {
		t.Fatal(err)
	}
	var originalEpoch time.Time
	f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT assigned_at FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='path_agent' AND source_ref=$3`, b, sources[b].AgentID, sources[b].TestID).Scan(&originalEpoch)
	})
	insert := func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO flow_capacity_agreement_sla_refs(tenant_id,agreement_id,version,agent_id,test_id,context_id,device_id,source_assigned_at)
            VALUES($1,$2,2,$3,$4,$5,$6,$7)`, b, records[b].ID, sources[b].AgentID, sources[b].TestID, f.contextID, f.routerID, originalEpoch)
		return err
	}
	// Exactly the same valid row must fail only under the other tenant's
	// application role/GUC; success under b rules out a broken-FK false pass.
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(a)), f.pool, insert); err == nil {
		t.Fatal("foreign source reference crossed storage tenant isolation")
	}
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(b)), f.pool, insert); err != nil {
		t.Fatal("foreign-write negative control used an invalid row", err)
	}
	foreignAgent := gouuid.NewString()
	foreignTest := seedVerdictCarrierTest(t, f, b, foreignAgent, "198.51.100.20")
	foreign := definitions[a]
	foreignTerms := *foreign.SLA
	foreignTerms.Sources = []flow.CarrierSLASource{{AgentID: foreignAgent, TestID: foreignTest.ID}}
	foreign.SLA = &foreignTerms
	if _, err := repository.SaveCapacityAgreement(tenancy.WithTenant(t.Context(), tenancy.ID(a)), f.users[a], flow.SaveCapacityAgreement{Definition: foreign}); !errors.Is(err, flow.ErrCapacityAgreementNotFound) {
		t.Fatal("foreign-only configured source became a local circuit selector", err)
	}
	if _, err := repository.SaveCapacityAgreement(tenancy.WithTenant(t.Context(), tenancy.ID(b)), f.users[b], flow.SaveCapacityAgreement{Definition: foreign}); err != nil {
		t.Fatal("foreign-source negative control used an unavailable source", err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='path_agent' AND source_ref=$3`, a, sources[a].AgentID, sources[a].TestID)
		return err
	})
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_capacity_agreement_sla_refs WHERE tenant_id=$1`, tenant).Scan(&count)
			if err == nil && (tenant == a && count != 0 || tenant == b && count != 3) {
				t.Fatal("source retirement crossed tenants or left a live retired reference", count)
			}
			return err
		})
		record, err := repository.GetCapacityAgreement(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.users[tenant], records[tenant].ID, "1")
		if record.SLASourceMetadataTrusted != (tenant == b) {
			t.Fatal("retired or sibling source metadata proof was substituted")
		}
		if err != nil || record.Definition.SLA == nil || len(record.Definition.SLA.Sources) != 1 || record.Definition.SLA.Sources[0].AgentID != sources[tenant].AgentID {
			t.Fatal("source retirement erased immutable contract terms", err)
		}
	}
	// Reusing the same key after an assignment change cannot revive its old
	// recorded epoch. A new operator revision must capture the new binding.
	f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='path_agent' AND source_ref=$3`, b, sources[b].AgentID, sources[b].TestID)
		return err
	})
	bound := tenancy.WithTenant(t.Context(), tenancy.ID(b))
	old, err := repository.GetCapacityAgreement(bound, f.users[b], records[b].ID, "1")
	if err != nil || old.SLASourceMetadataTrusted {
		t.Fatal("replacement binding revived an old recorded source epoch", err)
	}
	fresh, err := repository.SaveCapacityAgreement(bound, f.users[b], flow.SaveCapacityAgreement{ID: records[b].ID, Version: "2", Definition: definitions[b]})
	if err != nil || fresh.Version != "3" || !fresh.SLASourceMetadataTrusted {
		t.Fatal("explicit source relink did not capture its new assignment", err)
	}
}
