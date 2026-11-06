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
	"net/netip"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual application-role Postgres and registry writers; issued identities are
// seeded. This does not claim sender wire or query/surface integration.
func TestInterfaceRoleFlowBindingsKeepCurrentExplicitOriginsAndTenantScope(t *testing.T) {
	f := newRoleInputsFixture(t)
	const agent, address = "role-flow", "192.0.2.1"
	serials := map[string]string{}
	for _, tenant := range f.tenants {
		serials[tenant] = strings.ReplaceAll(gouuid.NewString(), "-", "")
		if err := NewAgentIdentities(f.pool).Record(t.Context(), tenant, agent, crypto.EntitySPIFFEID(tenant, agent), serials[tenant], time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`, tenant, agent, f.contextID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,$2,'flow_exporter',$3,$4,$5)`, tenant, agent, address, f.contextID, f.routerID)
			return err
		})
	}
	write := func(tenant string) string {
		t.Helper()
		id := gouuid.NewString()
		claim := entity.Observation{ID: id, Source: entity.SourceKey{AgentID: agent, Kind: entity.FlowExporter, SourceRef: address}, Alias: entity.AliasKey{Kind: entity.FlowExporterAlias, Value: address + "/ipfix/4294967295"}, SourceRef: "flow:ipfix:domain:4294967295", ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}
		accepted, unresolved, err := NewEntityRegistry(f.pool).WriteEvidenceBatch(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), agent, serials[tenant], []entity.Observation{claim})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("current explicit flow source was not accepted", accepted, unresolved, err)
		}
		return id
	}
	load := func(tenant string, budget entity.InterfaceRolePolicyBudget) ([]InterfaceRoleFlowBinding, error) {
		var out []InterfaceRoleFlowBinding
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = NewInterfaceRoleInputs(f.pool).FlowBindingsInScope(ctx, sc, entity.Scope{TenantID: tenant, ContextID: f.contextID}, budget)
			return err
		})
		return out, err
	}
	owners := func(tenant string, budget entity.InterfaceRolePolicyBudget) ([]InterfaceRoleExporterOwner, error) {
		var out []InterfaceRoleExporterOwner
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = NewInterfaceRoleInputs(f.pool).ExporterOwnersInScope(ctx, sc, budget)
			return err
		})
		return out, err
	}
	for _, tenant := range f.tenants {
		write(tenant)
		out, err := load(tenant, roleInputsBudget())
		if err != nil || len(out) != 1 || out[0].TenantID != tenant || out[0].ContextID != f.contextID || out[0].AgentID != agent || out[0].RouterID != f.routerID || out[0].Exporter != netip.MustParseAddr(address) || out[0].Protocol != "ipfix" || out[0].Domain != 4294967295 || !out[0].ValidUntil.After(time.Now()) || !strings.HasPrefix(out[0].SourceID, "evidence/") {
			t.Fatal("role flow binding lost current explicit origin or tenant scope", out, err)
		}
		owned, err := owners(tenant, roleInputsBudget())
		if err != nil || len(owned) != 1 || owned[0].TenantID != tenant || owned[0].ContextID != f.contextID || owned[0].AgentID != agent || owned[0].RouterID != f.routerID || owned[0].Exporter != netip.MustParseAddr(address) {
			t.Fatal("role exporter ownership lost complete tenant configuration", owned, err)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	// A second configured collector has NO observation. Dropping it because
	// it lacks current evidence would let an untrusted row choose the first
	// collector's context. Keep the complete operator ownership boundary.
	const competing = "role-flow-without-observations"
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`, a, competing, f.contextID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,$2,'flow_exporter',$3,$4,$5)`, a, competing, address, f.contextID, f.routerID)
		return err
	})
	if out, err := owners(a, roleInputsBudget()); err != nil || len(out) != 0 {
		t.Fatal("unobserved competing collector manufactured unique role ownership", out, err)
	}
	if out, err := owners(b, roleInputsBudget()); err != nil || len(out) != 1 || out[0].TenantID != b {
		t.Fatal("ambiguous exporter ownership damaged another tenant", out, err)
	}
	if out, err := owners(b, entity.InterfaceRolePolicyBudget{MemoryBytes: 4096, WorkUnits: 1}); !errors.Is(err, entity.ErrInterfaceRoleBudget) || out != nil {
		t.Fatal("role exporter ownership returned a partial admission result", out, err)
	}
	if err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(b)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		out, err := NewInterfaceRoleInputs(f.pool).FlowBindingsInScope(ctx, sc, entity.Scope{TenantID: a, ContextID: f.contextID}, roleInputsBudget())
		if !errors.Is(err, entity.ErrScopeMismatch) || out != nil {
			t.Fatal("foreign tenant reached role flow source storage", out, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if out, err := load(a, entity.InterfaceRolePolicyBudget{MemoryBytes: 4096, WorkUnits: 1}); !errors.Is(err, entity.ErrInterfaceRoleBudget) || out != nil {
		t.Fatal("role flow source returned a partial admission result", out, err)
	}
	latest := write(a)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET expires_at=observed_at+interval '1 microsecond' WHERE tenant_id=$1 AND observation_id=$2`, a, latest)
		return err
	})
	if out, err := load(a, roleInputsBudget()); err != nil || len(out) != 0 {
		t.Fatal("expired latest flow identity revived an older source", out, err)
	}
	write(a)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET anchor_entity_id=NULL WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='flow_exporter'`, a, agent)
		return err
	})
	write(a) // current inferred device identity is deliberately legitimate
	if out, err := load(a, roleInputsBudget()); err != nil || len(out) != 0 {
		t.Fatal("inferred flow identity supplied explicit origin authority", out, err)
	}
	if out, err := load(b, roleInputsBudget()); err != nil || len(out) != 1 || out[0].TenantID != b {
		t.Fatal("source refusal damaged another tenant's binding", out, err)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE agent_identities SET revoked_at=now() WHERE tenant_id=$1 AND agent_id=$2`, b, agent); err != nil {
		t.Fatal(err)
	}
	if out, err := load(b, roleInputsBudget()); err != nil || len(out) != 0 {
		t.Fatal("revoked flow sender retained role source authority", out, err)
	}
}
