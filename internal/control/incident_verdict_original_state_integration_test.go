// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"reflect"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentVerdictJoinsOriginalInterfaceStatesAndRejectsChangedDocuments(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	seedInterfaceRoleMCPConsent(f)
	type selected struct {
		actor    *auth.Principal
		id       string
		from, to time.Time
		before   incidentVerdictSnapshot
	}
	lanes := map[string]*selected{}
	for lane, tenant := range f.tenants {
		value := &selected{id: gouuid.NewString()}
		lanes[tenant] = value
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, permTestRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if _, err := (store.InterfaceRoleConfiguration{}).PutOverride(ctx, sc, f.contextID, f.interfaceID, "", "0", entity.InterfaceRoleBackbone); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'original interface verdict',$3,$4,true)`, tenant, value.id, f.contextID, f.interfaceID)
			return err
		})
		at := f.observedAt(tenant)
		value.from, value.to = at.Add(-time.Microsecond), at.Add(time.Microsecond)
		oper, admin := uint32(2-lane), uint32(1)
		claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "7"}, SourceRef: "snmp:ifIndex:7", InterfaceDescription: "owned backbone", ObservedAt: at, SNMPInterfaceState: &entity.SNMPInterfaceState{Version: 1, OperStatus: &oper, AdminStatus: &admin}}
		accepted, unresolved, err := writeEntityEvidenceBatchForTest(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), store.NewEntityRegistry(f.pool), "role-snmp", f.serials[tenant+"role-snmp"], []entity.Observation{claim})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("original typed point did not persist", accepted, unresolved, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				value.actor = auth.ClonePrincipal(current.principal)
			}
			return err
		})
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		value.before, err = f.server.loadIncidentVerdictSnapshot(ctx, value.actor, value.id, value.from, value.to, 64<<20, nil)
		if err != nil || len(value.before.states) != 1 || !value.before.states[0].Available || len(value.before.evidence.interfaces) != 1 || value.before.evidence.interfaces[0].role.Role != interfaceRoleBackbone {
			t.Fatal("joined original state/role population is incomplete", len(value.before.states), len(value.before.evidence.interfaces), err)
		}
		got, err := f.server.computeIncidentVerdict(ctx, value.actor, value.id, value.from, value.to, 128<<20)
		want := incident.FaultYourNetwork
		if lane == 1 {
			want = incident.FaultUnknown
		}
		if err != nil || got.Domain != want {
			t.Fatal("joined original state selected the wrong tenant/domain", got, err)
		}
		// A one-nanosecond half-open window still contains the original
		// microsecond Postgres point at its inclusive lower bound.
		point := value.before.states[0].ObservedAt
		narrow, err := f.server.computeIncidentVerdict(ctx, value.actor, value.id, point, point.Add(time.Nanosecond), 128<<20)
		if err != nil || narrow.Domain != want || len(narrow.Hypotheses[0].For)+len(narrow.Hypotheses[0].Against) != 1 {
			t.Fatal("nanosecond window lost its original retained point", narrow.Domain, want, err)
		}
		proveIncidentVerdictServedReaders(t, f, tenant, value.id, incident.VerdictInput{From: value.from, To: value.to}, got)
		citations := got.Hypotheses[0].For
		if lane == 1 {
			citations = got.Hypotheses[0].Against
		}
		if len(citations) != 1 || citations[0].EvidenceID != value.before.states[0].EvidenceID || citations[0].ContextID != f.contextID || citations[0].EntityID != f.interfaceID {
			t.Fatal("verdict lost its exact original citation", citations)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	proveIncidentVerdictForeignReaderRefusal(t, f, a, lanes[b].id, incident.VerdictInput{From: lanes[b].from, To: lanes[b].to})
	value := lanes[a]
	original := value.before.states[0]
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET snmp_interface_state='{"version":1,"oper_status":1,"admin_status":1}'::jsonb WHERE tenant_id=$1 AND id=$2`, a, original.EvidenceID)
		return err
	})
	ctxA := tenancy.WithTenant(t.Context(), tenancy.ID(a))
	if got, err := f.server.loadIncidentVerdictSnapshot(ctxA, value.actor, value.id, value.from, value.to, 64<<20, &value.before); err == nil || !reflect.DeepEqual(got, incidentVerdictSnapshot{}) {
		t.Fatal("changed original document retained publication authority", err)
	}
	other := lanes[b]
	if got, err := f.server.computeIncidentVerdict(tenancy.WithTenant(t.Context(), tenancy.ID(b)), other.actor, other.id, other.from, other.to, 128<<20); err != nil || got.Domain != incident.FaultUnknown || len(got.Hypotheses[0].Against) != 1 {
		t.Fatal("tenant A mutation changed tenant B's original verdict", got, err)
	}
	t.Log("real-integration: paired app-role PG/RLS typed original-state/role/canonical-membership join and changed-document publication refusal; SNMP inputs/sender identities modeled, real mTLS and four lab faults remain separate requirements")
}
