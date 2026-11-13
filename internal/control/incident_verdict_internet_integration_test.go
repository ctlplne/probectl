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
	"strings"
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

// Real app-role storage and ordered routing generations; protocol metadata
// here is modeled. Physical routed fault/receiver qualification is separate.
func seedInternetRoutingView(t *testing.T, f *roleExplanationAPIFixture, tenant string, origin uint32) store.BGPRoutingStagedView {
	t.Helper()
	raw := internetPhysicalUpForTest(64500, 4294967295)
	open := append([]byte(nil), raw[68:105]...)
	definition := store.BGPRoutingViewDefinition{Kind: "loc_rib", AFI: 1, SAFI: 1, Peer: store.BGPRoutingPeer{Type: 3, ASN: 64500, BGPIdentifier: netip.MustParseAddr("192.0.2.1"), SentOpen: open, ReceivedOpen: append([]byte(nil), open...)}}
	profile := store.BGPRoutingBudget{MemoryBytes: 64 << 20, WorkUnits: 64 << 20, StateBytes: 128 << 20, LeaseDuration: 5 * time.Minute}
	input := store.BGPRoutingPeerUpInput{CollectorAgentID: "role-listener", SenderSerial: f.serials[tenant+"role-listener"], SourceRef: "role-router", OriginSerial: f.serials[tenant+"role-router"], ObservationID: gouuid.NewString(), ObservedAt: f.observedAt(tenant), FrameDigest: crypto.Hash([]byte("modeled routing view " + tenant)), Definitions: []store.BGPRoutingViewDefinition{definition}}
	write := func(fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), tenant, entity.ErrScopeMismatch, func(ctx context.Context) error { return tenancy.InTenant(ctx, f.pool, fn) })
		if err != nil {
			t.Fatal(err)
		}
	}
	var staged store.BGPRoutingStageResult
	write(func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		staged, err = (store.BGPRouting{}).StagePeerInScope(ctx, sc, input, profile)
		return err
	})
	if staged.Status != "staged" || len(staged.Views) != 1 {
		t.Fatal("complete modeled routing view not staged", staged.Status)
	}
	for sequence := int64(1); sequence <= 2; sequence++ {
		stream := store.BGPRoutingStreamInput{CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: input.SourceRef, OriginSerial: input.OriginSerial, Generation: input.ObservationID, Sequence: sequence, ObservedAt: f.observedAt(tenant)}
		write(func(ctx context.Context, sc tenancy.Scope) error {
			result, err := (store.BGPRouting{}).ApplyPeerMessageInScope(ctx, sc, stream, profile, func(context.Context, store.BGPRoutingPeer, []store.BGPRoutingStagedView) ([]store.BGPRoutingBatch, error) {
				batch := store.BGPRoutingBatch{AFI: 1, SAFI: 1, EndOfRIB: sequence == 2}
				if sequence == 1 {
					batch.Changes = []store.BGPRoutingChange{{Prefix: netip.MustParsePrefix("198.19.0.0/24"), Segments: []store.BGPRoutingSegment{{Kind: 2, Values: []uint32{4294967295, origin}}}, Attributes: store.BGPRoutingAttributes{Wire: []store.BGPRoutingAttribute{}}, NextHops: []netip.Addr{netip.MustParseAddr("192.0.2.7")}}}
				}
				return []store.BGPRoutingBatch{batch}, nil
			})
			if err == nil && result.Status != "applied" {
				return fmt.Errorf("routing message was %s: %s", result.Status, result.Reason)
			}
			return err
		})
	}
	return staged.Views[0]
}

func TestIncidentInternetRoutingUsesCurrentCanonicalTenantAndRechecksOriginalView(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	snapshots := map[string]incidentVerdictSnapshot{}
	for lane, tenant := range f.tenants {
		ref := seedInternetRoutingView(t, f, tenant, uint32(64497+lane))
		key := incidentVerdictRouteKey{ContextID: f.contextID, RouterID: f.routerID, Address: "198.19.0.1"}
		snapshot := incidentVerdictSnapshot{evidence: incidentVerdictEvidence{tenantID: tenant, tests: []incidentVerdictTest{{source: store.IncidentConfiguredTest{TenantID: tenant, ContextID: f.contextID, EntityID: f.routerID}, reads: []store.IncidentTestMeasurement{{Available: true, ICMP: &entity.ICMPMeasurement{Version: 2, NetworkErrors: []entity.ICMPNetworkError{{Responder: key.Address}}}}}}}}}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err != nil {
				return err
			}
			return f.server.loadIncidentVerdictRoutes(ctx, sc, auth.ClonePrincipal(current.principal), &snapshot, nil, 16<<20)
		})
		if err != nil || len(snapshot.routes) != 1 || snapshot.routes[0].Route == nil {
			t.Fatal("canonical owned routing context not joined", err)
		}
		route := snapshot.routes[0].Route
		if route.Source.TenantID != tenant || route.View != ref.BGPRoutingViewRef || len(route.Paths) != 1 || route.Paths[0].Segments[0].Values[1] != uint32(64497+lane) {
			t.Fatal("routing context changed tenant, original view or complete path")
		}
		snapshots[tenant] = snapshot
	}
	a, b := f.tenants[0], f.tenants[1]
	original := snapshots[a]
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(a))
	var repeated incidentVerdictSnapshot
	err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[a])
		if err != nil {
			return err
		}
		return f.server.loadIncidentVerdictRoutes(ctx, sc, auth.ClonePrincipal(current.principal), &repeated, &original, 16<<20)
	})
	if err != nil || len(repeated.routes) != 1 || repeated.routes[0].Digest != original.routes[0].Digest {
		t.Fatal("unchanged original routing context changed during publication", err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id='role-listener' AND source_kind='bmp_peer' AND source_ref='role-router'`, a)
		return err
	})
	for _, tenant := range []string{a, b} {
		before := snapshots[tenant]
		var after incidentVerdictSnapshot
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err != nil {
				return err
			}
			return f.server.loadIncidentVerdictRoutes(ctx, sc, auth.ClonePrincipal(current.principal), &after, &before, 16<<20)
		})
		if err != nil || len(after.routes) != 1 {
			t.Fatal("routing withdrawal recheck failed", err)
		}
		if tenant == a && (after.routes[0].Route != nil || after.routes[0].Digest == before.routes[0].Digest) {
			t.Fatal("withdrawn original source retained routing authority")
		}
		if tenant == b && (after.routes[0].Route == nil || after.routes[0].Digest != before.routes[0].Digest) {
			t.Fatal("source withdrawal crossed tenant storage boundary")
		}
	}
	t.Log("real-integration: app-role Postgres/RLS, complete ordered per-tenant RIBs, current actor and original-view/source withdrawal rechecks; metadata modeled, physical routed labs owed")
}

func TestIncidentInternetServesCompleteConfiguredPopulationAndTenantIsolation(t *testing.T) {
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
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'internet original evidence',$3,$4,true)`, tenant, id, f.contextID, f.routerID); err != nil {
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
		for index := range definitions {
			definitions[index].Params["count"] = "100000"
			params, err := json.Marshal(definitions[index].Params)
			if err != nil {
				t.Fatal(err)
			}
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE tests SET params=$1::jsonb,updated_at=clock_timestamp() WHERE id=$2`, params, definitions[index].ID)
				return err
			})
		}
		seedInternetRoutingView(t, f, tenant, 64497)
		raw := internetPhysicalUpForTest(64500, 4294967295)
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
			m := &entity.ICMPMeasurement{Version: 2, DefinitionHash: digest, StartedAt: at.Add(time.Microsecond), CompletedAt: observed, Requested: 100000, Attempted: 100000, Transmitted: 100000, ReadComplete: true}
			for sequence := range m.Requested {
				m.NetworkErrors = append(m.NetworkErrors, entity.ICMPNetworkError{Sequence: sequence, Responder: "198.19.0.1", Type: 3, ReceivedAt: observed, PacketDigest: strings.Repeat("a", 64)})
			}
			if lane == 1 {
				m.Replies = 100000
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
		got, err := f.server.queryIncidentVerdict(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), actor, id, windows[tenant])
		want := incident.FaultWiderInternet
		if lane == 1 {
			want = incident.FaultUnknown
		}
		if err != nil || got.Domain != want {
			t.Fatal("stored complete network-error population selected the wrong tenant/domain", got.Domain, want, err)
		}

		found := false
		for _, citation := range got.Hypotheses[2].For {
			if citation.Routing != nil && citation.Routing.OriginASN == 64497 && citation.Routing.Address == "198.19.0.1" {
				found = true
			}
		}
		if lane == 0 && !found {
			t.Fatal("original selected-prefix routing context disappeared")
		}
		proveIncidentVerdictServedReaders(t, f, tenant, id, windows[tenant], got)
		proveIncidentVerdictSignedExport(t, f, tenant, id, windows[tenant], got)
	}
	proveIncidentVerdictForeignReaderRefusal(t, f, f.tenants[0], ids[f.tenants[1]], windows[f.tenants[1]])
	t.Log("real-integration: issued evidence mTLS, pooled RLS, current ASN/prefix/interface association and HTTPS REST/SDK/CLI/native/signed readers in two tenants; complete100000 outcomes on each of two independent configured senders per tenant and original BMP/SNMP/ICMP/RIB metadata modeled; routed physical fault labs remain owed")
}
