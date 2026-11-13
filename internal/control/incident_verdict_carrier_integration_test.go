// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

func seedVerdictCarrierTest(t *testing.T, f *roleExplanationAPIFixture, tenant, sender, target string) testspec.ExecutableDefinition {
	t.Helper()
	definition := testspec.ExecutableDefinition{ID: gouuid.NewString(), Type: "icmp", Target: target, IntervalSeconds: 10, TimeoutSeconds: 1, Params: map[string]string{"allow_private_targets": "true", "count": "3"}}
	params, err := json.Marshal(definition.Params)
	if err != nil {
		t.Fatal(err)
	}
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (store.Agents{}).Register(ctx, sc, sender, "carrier measurement "+sender, "127.0.0.1", "fixture", crypto.AgentSPIFFEID(tenant, sender), nil); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled) VALUES($1,$2,'carrier measurement '||$2::uuid::text,'icmp',$3,10,1,$4::jsonb,true)`, tenant, definition.ID, target, params); err != nil {
			return err
		}
		registry := store.NewEntityRegistry(f.pool)
		if err := registry.AssignPathTestContext(ctx, sc, definition.ID, f.contextID); err != nil {
			return err
		}
		return registry.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: sender, Kind: entity.PathAgent, SourceRef: definition.ID}, f.contextID, f.routerID)
	})
	return definition
}

func TestIncidentCarrierServesOriginalASNHandoffAndTenantIsolation(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	seedInterfaceRoleMCPConsent(f)
	sender := newVerdictEvidenceSender(t, f)
	backboneID := gouuid.NewString()
	ids := map[string]string{}
	windows := map[string]incident.VerdictInput{}
	for lane, tenant := range f.tenants {
		id := gouuid.NewString()
		ids[tenant] = id
		var actor *auth.Principal
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, permTestRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			policy, err := (store.InterfaceRoleConfiguration{}).Policy(ctx, sc, f.contextID, roleExplanationStoreBudget())
			if err != nil {
				return err
			}
			policy.Definition.ProviderASNs = []uint32{4294967295}
			if _, err := (store.InterfaceRoleConfiguration{}).PutPolicy(ctx, sc, f.contextID, policy.ID, policy.Revision, policy.Definition, roleExplanationStoreBudget()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id,source_agent_id,configured_ref,interface_index) VALUES($1,$2,$3,'interface','local backbone',$4,'role-snmp','192.0.2.1',8)`, tenant, f.contextID, backboneID, f.routerID); err != nil {
				return err
			}
			if _, err := (store.InterfaceRoleConfiguration{}).PutOverride(ctx, sc, f.contextID, backboneID, "", "0", entity.InterfaceRoleBackbone); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'carrier original evidence',$3,$4,true)`, tenant, id, f.contextID, f.routerID); err != nil {
				return err
			}
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				actor = auth.ClonePrincipal(current.principal)
			}
			return err
		})
		f.peer(tenant, 4294967295)
		listener, snmp := sender(tenant, "role-listener"), sender(tenant, "role-snmp")
		pollAt := f.observedAt(tenant)
		prefixes := append(roleExplanationPrefixes(), entity.SNMPInterfacePrefix{IfIndex: 8, Prefix: netip.MustParsePrefix("198.18.0.0/24"), OnLink: true})
		source := entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}
		poll := []entity.Observation{{ID: gouuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.1"}, SourceRef: "snmp:configured-target", ObservedAt: pollAt, SNMPInterfacePrefixes: prefixes}}
		for _, row := range []struct{ index, address string }{{"7", "10.42.0.2"}, {"8", "198.18.0.1"}} {
			poll = append(poll, entity.Observation{ID: gouuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: row.index}, SourceRef: "snmp:ifIndex:" + row.index, ObservedAt: pollAt}, entity.Observation{ID: gouuid.NewString(), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: row.address}, SourceRef: "snmp:ifIndex:" + row.index, ObservedAt: pollAt})
		}
		if accepted, unresolved, err := snmp.Submit(t.Context(), poll); err != nil || accepted != len(poll) || unresolved != 0 {
			t.Fatal("whole current handoff/backbone poll refused", accepted, unresolved, err)
		}

		agents := []string{gouuid.NewString(), gouuid.NewString()}
		definitions := []testspec.ExecutableDefinition{seedVerdictCarrierTest(t, f, tenant, agents[0], "198.51.100.7"), seedVerdictCarrierTest(t, f, tenant, agents[1], "203.0.113.7")}
		clients := []interface {
			Submit(context.Context, []entity.Observation) (int, int, error)
		}{sender(tenant, agents[0]), sender(tenant, agents[1])}
		_, model := carrierVerdictFixture(t)
		raw := append([]byte(nil), model.interfaces[1].peerReads[0].Session.RawFrame...)
		copy(raw[28:32], []byte{10, 42, 0, 1})
		fact, err := bgp.DecodePhysicalPeerSession(t.Context(), raw, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		at := f.observedAt(tenant)
		claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: "role-listener", Kind: entity.BMPPeer, SourceRef: "role-router"}, Alias: entity.AliasKey{Kind: entity.BMPPeerAlias, Value: "10.42.0.1/as4294967295"}, SourceRef: "bmp:router:role-router:peer-asn:4294967295", OriginSerial: f.serials[tenant+"role-router"], ObservedAt: at, BMPPeerSession: fact}
		if accepted, unresolved, err := listener.Submit(t.Context(), []entity.Observation{claim}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("original handoff event refused", accepted, unresolved, err)
		}
		observed := f.observedAt(tenant)
		states := []entity.Observation{}
		for _, index := range []uint32{7, 8} {
			oper, admin := uint32(1), uint32(1)
			states = append(states, entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: fmt.Sprint(index)}, SourceRef: fmt.Sprint("snmp:ifIndex:", index), ObservedAt: observed, SNMPInterfaceState: &entity.SNMPInterfaceState{Version: 1, OperStatus: &oper, AdminStatus: &admin}})
		}
		if accepted, unresolved, err := snmp.Submit(t.Context(), states); err != nil || accepted != 2 || unresolved != 0 {
			t.Fatal("original local/handoff state refused", accepted, unresolved, err)
		}
		for i, definition := range definitions {
			digest, err := testspec.DefinitionHash(definition)
			if err != nil {
				t.Fatal(err)
			}
			m := &entity.ICMPMeasurement{Version: 1, DefinitionHash: digest, StartedAt: at.Add(time.Microsecond), CompletedAt: observed, Requested: 3, Attempted: 3, Transmitted: 3, ReadComplete: true}
			if lane == 1 {
				m.Replies = 3
				m.Responders = []string{definition.Target}
			}
			probe := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: agents[i], Kind: entity.PathAgent, SourceRef: definition.ID}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: definition.Target}, SourceRef: "icmp:configured-test", ObservedAt: observed, ICMP: m}
			if accepted, unresolved, err := clients[i].Submit(t.Context(), []entity.Observation{probe}); err != nil || accepted != 1 || unresolved != 0 {
				t.Fatal("original independent network result refused", accepted, unresolved, err)
			}
		}
		to := observed.Add(time.Microsecond)
		if delay := time.Until(to); delay > 0 {
			if delay > 5*time.Second {
				t.Fatal("fixture/host clock skew exceeds proof admission")
			}
			time.Sleep(delay)
		}
		windows[tenant] = incident.VerdictInput{From: at, To: to}
		got, err := f.server.computeIncidentVerdict(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), actor, id, at, to, 128<<20)
		want := incident.FaultCarrier
		if lane == 1 {
			want = incident.FaultUnknown
		}
		if err != nil || got.Domain != want {
			snapshot, debugErr := f.server.loadIncidentVerdictSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), actor, id, at, to, 64<<20, nil)
			t.Log("carrier snapshot", "sources", len(snapshot.sources), "states", len(snapshot.states), "peers", len(snapshot.peerSessions), "tests", len(snapshot.tests), "outcomes", len(snapshot.outcomes), "interfaces", len(snapshot.evidence.interfaces), "error", debugErr)
			for _, item := range snapshot.evidence.interfaces {
				t.Log("owned interface", item.source.EntityID, "current", item.source.Current, "role", item.role.Role, "snmp", item.role.SNMPCurrent, "prefix", item.role.PrefixCurrent, "reads", len(item.reads), "peerReads", len(item.peerReads))
			}
			t.Fatal("stored carrier originals selected the wrong tenant/domain", got.Domain, want, err, got.Hypotheses)
		}
		found := false
		for _, citation := range got.Hypotheses[1].For {
			if citation.PeerASN == 4294967295 && citation.HandoffInterfaceID == f.interfaceID {
				found = true
			}
		}
		if !found {
			t.Fatal("actual ASN/hand-off association disappeared")
		}
		proveIncidentVerdictServedReaders(t, f, tenant, id, windows[tenant], got)
		proveIncidentVerdictSignedExport(t, f, tenant, id, windows[tenant], got)
	}
	proveIncidentVerdictForeignReaderRefusal(t, f, f.tenants[0], ids[f.tenants[1]], windows[f.tenants[1]])
	t.Log("real-integration: issued evidence mTLS, pooled RLS, current ASN/prefix/interface association and HTTPS REST/SDK/CLI/native/signed readers in two tenants; original BMP/SNMP/ICMP outcomes modeled, routed physical fault labs remain owed")
}
