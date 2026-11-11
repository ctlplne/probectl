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
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual RLS/current grants/effective-tag resolver with modeled source facts.
// Neither context has a flow exporter; this proves complete current membership,
// not original counter availability, historical membership or served billing.
func TestCapacityCircuitKeepsCompleteEffectiveMembersAndCurrentTenantAuthority(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	tagID, otherContext, otherDevice, otherInterface := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	value := strings.Repeat("跨域🚀", 4097)
	actors := map[string]*auth.Principal{}
	assignments := map[string]string{}
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permTagsRead); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES($1,$2,'capacity_circuit')`, tenant, tagID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'other site','other VRF')`, tenant, otherContext, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','other circuit device')`, tenant, otherContext, otherDevice); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id) VALUES($1,$2,$3,'interface','other circuit interface',$4)`, tenant, otherContext, otherInterface, otherDevice); err != nil {
				return err
			}
			scope := tags.Scope{TenantID: tenant, ContextID: otherContext}
			assignment, err := (store.TagAssignments{}).CreateManual(ctx, sc, store.ManualTagAssignmentInput{Scope: scope, TagID: tagID, TargetKind: "interface", TargetID: otherInterface, Value: value})
			if err != nil {
				return err
			}
			assignments[tenant] = assignment.ID
			_, err = (store.TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: f.contextID}, TagID: tagID, TargetKind: "interface", Match: "snmp_field",
				SNMPField: "if_descr", SNMPValue: "owned-" + strconv.Itoa(lane), Value: value})
			if err != nil {
				return err
			}
			grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			actors[tenant] = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: f.users[tenant], ViaBearerToken: true}, grants)
			return err
		})
	}
	read := func(tenant string) store.CapacityCircuitSnapshot {
		t.Helper()
		got, err := f.server.loadCapacityCircuit(t.Context(), actors[tenant], tagID, value, 128<<20)
		if err != nil || got.TenantID != tenant || got.TagID != tagID || got.Value != value || len(got.Members) != 2 || got.Revision <= 0 {
			t.Fatal("complete current circuit lost manual/SNMP members, long Unicode value or tenant", got, err)
		}
		found := map[string]bool{}
		for _, member := range got.Members {
			if member.Scope.TenantID != tenant {
				t.Fatal("circuit mixed tenants")
			}
			found[member.InterfaceID] = true
		}
		if !found[f.interfaceID] || !found[otherInterface] {
			t.Fatal("circuit membership was restricted to exporter bindings or one context", found)
		}
		return got
	}
	a, b := f.tenants[0], f.tenants[1]
	before := read(a)
	read(b)
	if err := f.server.recheckCapacityCircuit(t.Context(), actors[a], before, 128<<20); err != nil {
		t.Fatal("unchanged effective circuit was not reusable within the operation", err)
	}
	if got, err := f.server.loadCapacityCircuit(tenancy.WithTenant(t.Context(), tenancy.ID(b)), actors[a], tagID, value, 128<<20); err == nil || !reflect.DeepEqual(got, store.CapacityCircuitSnapshot{}) {
		t.Fatal("circuit replaced contradictory tenant scope", got, err)
	}
	// A denied later context must discard every earlier selected member.
	denyContext := max(f.contextID, otherContext)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := store.NewTagSnapshots(f.pool).CapacityCircuitInScope(ctx, sc, tagID, value, 128<<20, func(_ context.Context, record entity.ContextRecord) error {
			if record.ContextID == denyContext {
				return errors.New("context deliberately unreadable")
			}
			return nil
		})
		if err == nil || !reflect.DeepEqual(got, store.CapacityCircuitSnapshot{}) {
			t.Fatal("unreadable potential members silently shortened the circuit", got, err)
		}
		if got, err := store.NewTagSnapshots(f.pool).CapacityCircuitInScope(ctx, sc, tagID, value, 128<<20, nil); err == nil || !reflect.DeepEqual(got, store.CapacityCircuitSnapshot{}) {
			t.Fatal("missing context authorizer granted a circuit snapshot", got, err)
		}
		return nil
	})
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.TagAssignments{}).UpdateManual(ctx, sc, assignments[a], store.ManualTagAssignmentInput{Scope: tags.Scope{TenantID: a, ContextID: otherContext}, TagID: tagID,
			TargetKind: "interface", TargetID: otherInterface, Value: "different circuit"})
		return err
	})
	if err := f.server.recheckCapacityCircuit(t.Context(), actors[a], before, 128<<20); err == nil {
		t.Fatal("changed effective membership retained the old complete read authority")
	}
	current, err := f.server.loadCapacityCircuit(t.Context(), actors[a], tagID, value, 128<<20)
	if err != nil || len(current.Members) != 1 || current.Members[0].InterfaceID != f.interfaceID {
		t.Fatal("new membership revision did not reflect the manual change", current, err)
	}
	read(b)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permTagsRead)
		return err
	})
	if got, err := f.server.loadCapacityCircuit(t.Context(), actors[a], tagID, value, 128<<20); err == nil || !reflect.DeepEqual(got, store.CapacityCircuitSnapshot{}) {
		t.Fatal("withdrawn current tag grant retained circuit membership", got, err)
	}
	read(b)
}
