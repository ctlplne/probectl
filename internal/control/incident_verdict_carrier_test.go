// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testspec"
)

func carrierVerdictFixture(t *testing.T) (context.Context, incidentVerdictEvidence) {
	t.Helper()
	ctx, input := verdictClassifierFixture()
	const area = "9df966f1-6882-4654-8cd4-7d3cc7898e73"
	const router = "71e9f275-fbf2-4eca-bc75-1fb0e27b8724"
	const handoff = "a0000000-0000-4000-8000-000000000007"
	const backbone = "a0000000-0000-4000-8000-000000000008"
	at := input.from.Add(10 * time.Second)
	until := time.Now().UTC().Add(time.Hour)
	state := func(id, evidence string, index uint32, role interfaceRole) incidentVerdictInterface {
		oper, admin := uint32(1), uint32(1)
		source := store.IncidentInterfaceStateSource{TenantID: input.tenantID, ContextID: area, EntityID: id, RouterID: router, AgentID: "snmp", ConfiguredRef: "192.0.2.1", SourceGeneration: 1, IfIndex: index, Current: true, CurrentSince: input.from.Add(-time.Hour), ValidUntil: &until}
		return incidentVerdictInterface{source: source, direct: true, role: interfaceRoleExplanation{Scope: entity.Scope{TenantID: input.tenantID, ContextID: area}, InterfaceID: id, Role: role, SNMPCurrent: true, PrefixCurrent: true}, reads: []store.IncidentInterfaceStateMeasurement{{TenantID: input.tenantID, ContextID: area, EntityID: id, AgentID: "snmp", ConfiguredRef: source.ConfiguredRef, SourceGeneration: 1, IfIndex: index, EvidenceID: evidence, ObservedAt: at.Add(time.Second), Available: true, OriginalSenderValid: true, CaptureDigest: [32]byte{3}, State: &entity.SNMPInterfaceState{Version: 1, OperStatus: &oper, AdminStatus: &admin}}}}
	}
	transit := state(handoff, "b0000000-0000-4000-8000-000000000007", 7, interfaceRoleTransit)
	clock := store.InterfaceRoleEvidenceClock{ObservedAt: input.from.Add(-time.Minute), ValidUntil: until}
	transit.roleInputs = store.InterfaceRoleInputs{Scope: transit.role.Scope, InterfaceID: handoff, RouterID: router, IfIndex: 7,
		Policy: entity.InterfaceRolePolicyRecord{Scope: transit.role.Scope, Definition: entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{4294967295}}, UpdatedAt: input.from.Add(-time.Hour)},
		SNMP: &store.InterfaceRoleSNMPInputs{InterfaceRoleEvidenceClock: clock, SourceID: "evidence/snmp", PrefixSourceID: "evidence/prefix", PrefixClock: clock,
			Prefixes: []entity.SNMPInterfacePrefix{{IfIndex: 7, Prefix: netip.MustParsePrefix("192.0.2.0/24"), OnLink: true}},
			Bindings: []store.InterfaceRoleBindingInput{{InterfaceRoleEvidenceClock: clock, InterfaceID: handoff, SourceID: "evidence/binding", IfIndex: 7}}}}
	notification := make([]byte, 21)
	for i := range 16 {
		notification[i] = 255
	}
	binary.BigEndian.PutUint16(notification[16:18], 21)
	notification[18], notification[19] = 3, 4
	raw := make([]byte, 49)
	raw[0], raw[5], raw[48] = 3, 2, 3
	copy(raw[28:32], []byte{192, 0, 2, 7})
	binary.BigEndian.PutUint32(raw[32:36], 4294967295)
	raw = append(raw, notification...)
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	fact, err := bgp.DecodePhysicalPeerSession(ctx, raw, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	transit.peerReads = []store.IncidentPeerSessionMeasurement{{TenantID: input.tenantID, ContextID: area, RouterID: router, SourceGeneration: 1, AgentID: "listener", ConfiguredRef: "physical-router", EvidenceID: "b0000000-0000-4000-8000-000000000001", ObservedAt: at, ValidUntil: &until, SourceCurrent: true, Session: fact, CaptureDigest: [32]byte{1}}}
	input.interfaces = []incidentVerdictInterface{state(backbone, "b0000000-0000-4000-8000-000000000008", 8, interfaceRoleBackbone), transit}
	for index, target := range []string{"198.51.100.7", "203.0.113.7"} {
		agent := []string{"agent-a", "agent-b"}[index]
		source := store.IncidentConfiguredTest{TenantID: input.tenantID, ContextID: area, EntityID: router, SourceGeneration: 1, TestID: []string{"c0000000-0000-4000-8000-000000000001", "c0000000-0000-4000-8000-000000000002"}[index], AgentID: agent, Type: "icmp", Target: target, CurrentSince: input.from.Add(-time.Hour), MeasurementIdentityUntil: &until,
			Definition: testspec.ExecutableDefinition{Type: "icmp", Target: target}}
		read := store.IncidentTestMeasurement{TenantID: input.tenantID, ContextID: area, EntityID: router, SourceGeneration: 1, TestID: source.TestID, AgentID: agent, Alias: target, Available: true, EvidenceID: []string{"d0000000-0000-4000-8000-000000000001", "d0000000-0000-4000-8000-000000000002"}[index], ObservedAt: at.Add(5 * time.Second), CaptureDigest: [32]byte{byte(index + 4)}, ICMP: &entity.ICMPMeasurement{Version: 1, StartedAt: at.Add(2 * time.Second), CompletedAt: at.Add(5 * time.Second), Requested: 3, Attempted: 3, Transmitted: 3, ReadComplete: true}}
		input.tests = append(input.tests, incidentVerdictTest{source: source, reads: []store.IncidentTestMeasurement{read}})
	}
	return ctx, input
}

func TestIncidentCarrierRequiresOriginalASNHandoffAndIndependentNetworkLoss(t *testing.T) {
	for _, name := range []string{"complete", "router-member handoff", "no canonical membership", "other router healthy", "no declared ASN", "other ASN", "late policy", "late prefix", "late binding", "late override", "HTTPS reply despite ICMP loss", "no local coverage", "disabled handoff", "same agent", "same destination", "external reply", "incomplete receive", "monitoring withdrawal", "ICMP filtering only", "foreign peer"} {
		t.Run(name, func(t *testing.T) {
			ctx, input := carrierVerdictFixture(t)
			peer := &input.interfaces[1].peerReads[0]
			switch name {
			case "router-member handoff":
				input.interfaces[1].direct = false
				input.interfaces[1].incidentRouter = true
				input.interfaces[0].direct = false
				input.interfaces[0].incidentRouter = true
			case "no canonical membership":
				input.interfaces[1].direct = false
			case "other router healthy":
				input.interfaces[0].source.RouterID = "a0000000-0000-4000-8000-000000000099"
			case "no declared ASN":
				input.interfaces[1].roleInputs.Policy.Definition.ProviderASNs = nil
			case "other ASN":
				input.interfaces[1].roleInputs.Policy.Definition.ProviderASNs = []uint32{64500}
			case "late policy":
				input.interfaces[1].roleInputs.Policy.UpdatedAt = peer.ObservedAt.Add(time.Second)
			case "late prefix":
				input.interfaces[1].roleInputs.SNMP.PrefixClock.ObservedAt = peer.ObservedAt.Add(time.Second)
			case "late binding":
				input.interfaces[1].roleInputs.SNMP.Bindings[0].ObservedAt = peer.ObservedAt.Add(time.Second)
			case "late override":
				input.interfaces[1].roleInputs.Override = &entity.InterfaceRoleOverrideRecord{Scope: input.interfaces[1].roleInputs.Scope, InterfaceID: input.interfaces[1].source.EntityID, Role: entity.InterfaceRoleTransit, UpdatedAt: peer.ObservedAt.Add(time.Second)}
			case "HTTPS reply despite ICMP loss":
				input.tests = append(input.tests, verdictHTTPTest(input, "agent-web", "e0000000-0000-4000-8000-000000000001", 200))
			case "no local coverage":
				input.interfaces[0].reads = nil
			case "disabled handoff":
				*input.interfaces[1].reads[0].State.AdminStatus = 2
			case "same agent":
				input.tests[1].source.AgentID = input.tests[0].source.AgentID
				input.tests[1].reads[0].AgentID = input.tests[0].source.AgentID
			case "same destination":
				input.tests[1].source.Target = input.tests[0].source.Target
				input.tests[1].source.Definition.Target = input.tests[0].source.Target
				input.tests[1].reads[0].Alias = input.tests[0].reads[0].Alias
			case "external reply":
				input.tests[1].reads[0].ICMP.Replies = 1
			case "incomplete receive":
				input.tests[1].reads[0].ICMP.ReadComplete = false
			case "monitoring withdrawal":
				raw := append([]byte(nil), peer.Session.RawFrame[:49]...)
				raw[48] = 5
				binary.BigEndian.PutUint32(raw[1:5], 49)
				fact, err := bgp.DecodePhysicalPeerSession(ctx, raw, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
				if err != nil {
					t.Fatal(err)
				}
				peer.Session = fact
			case "ICMP filtering only":
				input.interfaces[1].peerReads = nil
			case "foreign peer":
				peer.TenantID = "foreign"
			}
			got, err := classifyIncidentVerdict(ctx, input, 8<<20)
			if name == "foreign peer" {
				if !errors.Is(err, entity.ErrScopeMismatch) || got.Domain != "" {
					t.Fatal("foreign source entered a verdict", got.Domain, err)
				}
				return
			}
			want := incident.FaultUnknown
			if name == "complete" || name == "router-member handoff" {
				want = incident.FaultCarrier
			}
			if err != nil || got.Domain != want {
				t.Fatal("carrier result lost its required evidence boundary", name, got.Domain, want, err)
			}
			if name == "complete" || name == "router-member handoff" {
				if got.Confidence != "corroborated" || len(got.Hypotheses[1].For) != 5 {
					t.Fatal("original corroborating evidence was omitted", got.Hypotheses[1])
				}
				found := false
				for _, citation := range got.Hypotheses[1].For {
					if citation.PeerASN == 4294967295 && citation.HandoffInterfaceID == input.interfaces[1].source.EntityID {
						found = true
					}
				}
				if !found {
					t.Fatal("complete ASN or canonical hand-off was lost")
				}
				for _, citation := range got.Hypotheses[1].For {
					if citation.PeerASN == 0 {
						continue
					}
					if _, err := citation.SourceReference(); err != nil {
						t.Fatal(err)
					}
					for _, mutate := range []func(*incident.VerdictCitation){func(c *incident.VerdictCitation) { c.PeerASN = 0 }, func(c *incident.VerdictCitation) { c.HandoffInterfaceID = "foreign" }, func(c *incident.VerdictCitation) { c.SourceKind = "control_plane_path" }} {
						changed := citation
						mutate(&changed)
						if _, err := changed.SourceReference(); err == nil {
							t.Fatal("unpaired or foreign namespace carrier metadata accepted")
						}
					}
				}
			}
		})
	}
}

func TestIndependentNetworkLossKeepsWholeCohortAndStrictIntervals(t *testing.T) {
	_, input := carrierVerdictFixture(t)
	first, other := input.tests[0].reads[0], input.tests[1].reads[0]
	population := make([]incidentNetworkFailure, 0, 4097)
	for range 4096 {
		population = append(population, incidentNetworkFailure{read: first, target: first.Alias})
	}
	if independentOverlappingNetworkLoss(population) {
		t.Fatal("duplicates invented another vantage")
	}
	population = append(population, incidentNetworkFailure{read: other, target: other.Alias})
	if !independentOverlappingNetworkLoss(population) {
		t.Fatal("independent observation was hidden behind a cohort page")
	}
	other.ICMP.StartedAt = first.ICMP.CompletedAt
	other.ICMP.CompletedAt = other.ICMP.StartedAt.Add(time.Second)
	if independentOverlappingNetworkLoss([]incidentNetworkFailure{{read: first, target: first.Alias}, {read: other, target: other.Alias}}) {
		t.Fatal("touching execution intervals became contemporaneous loss")
	}
	other.ICMP.CompletedAt = other.ICMP.StartedAt
	if independentOverlappingNetworkLoss([]incidentNetworkFailure{{read: first, target: first.Alias}, {read: other, target: other.Alias}}) {
		t.Fatal("zero-length observation became corroboration")
	}
}
