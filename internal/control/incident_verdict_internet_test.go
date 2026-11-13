// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
)

func internetPhysicalUpForTest(local, remote uint32) []byte {
	open := func(asn uint32) []byte {
		raw := make([]byte, 37)
		for i := range 16 {
			raw[i] = 255
		}
		binary.BigEndian.PutUint16(raw[16:18], 37)
		raw[18], raw[19] = 1, 4
		wire := uint16(asn)
		if asn > 65535 {
			wire = 23456
		}
		binary.BigEndian.PutUint16(raw[20:22], wire)
		binary.BigEndian.PutUint16(raw[22:24], 90)
		copy(raw[24:28], []byte{192, 0, 2, 1})
		raw[28], raw[29], raw[30], raw[31], raw[32] = 8, 2, 6, 65, 4
		binary.BigEndian.PutUint32(raw[33:37], asn)
		return raw
	}
	raw := make([]byte, 68)
	raw[0], raw[5] = 3, 3
	copy(raw[28:32], []byte{192, 0, 2, 7})
	binary.BigEndian.PutUint32(raw[32:36], remote)
	copy(raw[36:40], []byte{192, 0, 2, 1})
	copy(raw[60:64], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(raw[64:66], 179)
	binary.BigEndian.PutUint16(raw[66:68], 20000)
	raw = append(raw, open(local)...)
	raw = append(raw, open(remote)...)
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	return raw
}

func internetVerdictFixture(t *testing.T) (context.Context, incidentVerdictEvidence) {
	t.Helper()
	ctx, input := carrierVerdictFixture(t)
	peer := &input.interfaces[1].peerReads[0]
	fact, err := bgp.DecodePhysicalPeerSession(ctx, internetPhysicalUpForTest(64500, 4294967295), bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	peer.Session = fact
	input.routes = map[incidentVerdictRouteKey]incidentVerdictRoute{}
	for i := range input.tests {
		read := &input.tests[i].reads[0]
		read.ICMP.Version = 2
		for sequence := range read.ICMP.Requested {
			read.ICMP.NetworkErrors = append(read.ICMP.NetworkErrors, entity.ICMPNetworkError{Sequence: sequence, Responder: "198.18.0.1", Type: 3, ReceivedAt: read.ICMP.CompletedAt, PacketDigest: strings.Repeat("a", 64)})
		}
		key := incidentVerdictRouteKey{ContextID: read.ContextID, RouterID: read.EntityID, Address: "198.18.0.1"}
		input.routes[key] = incidentVerdictRoute{Key: key, Digest: strings.Repeat("e", 64), Route: &store.BGPRoutingLookup{
			Source: store.BGPRoutingSource{Scope: entity.Scope{TenantID: input.tenantID, ContextID: read.ContextID}, RouterID: read.EntityID, CollectorAgentID: "router-listener", ObservedAt: input.from},
			View:   store.BGPRoutingViewRef{ID: "aee337be-624f-440c-9be9-be3e2c19f7c5", Generation: "bc646676-f577-4818-8b9a-59f9fa9f71ad"}, Prefix: netip.MustParsePrefix("198.18.0.0/24"),
			Paths:        []store.BGPRoutingChange{{Prefix: netip.MustParsePrefix("198.18.0.0/24"), Segments: []store.BGPRoutingSegment{{Kind: 2, Values: []uint32{4294967295, 64497}}}}},
			LastSequence: 2, LastObservedAt: peer.ObservedAt, ValidUntil: time.Now().UTC().Add(time.Hour)}}
	}
	return ctx, input
}

func TestIncidentInternetRequiresOriginalErrorsIndependentVantagesAndOwnedRouting(t *testing.T) {
	for _, name := range []string{"complete", "missing route", "wrong prefix", "owned local responder", "late route", "expired route", "ambiguous origin", "local origin", "provider origin", "not provider path", "same agent", "same target", "partial quote population", "conflicting outcome", "local IO", "echo reply", "nonrouting code", "peer down", "unknown lifecycle", "foreign route"} {
		t.Run(name, func(t *testing.T) {
			ctx, input := internetVerdictFixture(t)
			first := &input.tests[0].reads[0]
			var key incidentVerdictRouteKey
			for candidate := range input.routes {
				key = candidate
			}
			route := input.routes[key]
			switch name {
			case "missing route":
				delete(input.routes, key)
			case "owned local responder":
				input.interfaces[1].roleInputs.SNMP.Prefixes = append(input.interfaces[1].roleInputs.SNMP.Prefixes, entity.SNMPInterfacePrefix{IfIndex: 8, Prefix: netip.MustParsePrefix("198.18.0.0/24"), OnLink: true})
			case "wrong prefix":
				route.Route.Prefix = netip.MustParsePrefix("203.0.113.0/24")
			case "late route":
				route.Route.LastObservedAt = input.to
			case "expired route":
				route.Route.ValidUntil = input.from
			case "ambiguous origin":
				route.Route.Paths[0].Segments[0].Kind = 1
			case "local origin":
				route.Route.Paths[0].Segments[0].Values[1] = 64500
			case "provider origin":
				route.Route.Paths[0].Segments[0].Values[1] = 4294967295
			case "not provider path":
				route.Route.Paths[0].Segments[0].Values[0] = 64498
			case "same agent":
				input.tests[1].source.AgentID = input.tests[0].source.AgentID
				input.tests[1].reads[0].AgentID = input.tests[0].source.AgentID
			case "same target":
				input.tests[1].source.Target = first.Alias
				input.tests[1].source.Definition.Target = first.Alias
				input.tests[1].reads[0].Alias = first.Alias
			case "partial quote population":
				first.ICMP.NetworkErrors = first.ICMP.NetworkErrors[:1]
			case "conflicting outcome":
				first.ICMP.NetworkErrors[0].Conflicting = true
			case "local IO":
				first.ICMP.IOFailed = true
			case "echo reply":
				first.ICMP.Replies = 1
			case "nonrouting code":
				first.ICMP.NetworkErrors[0].Code = 1
			case "peer down":
				input.interfaces[1].peerReads[0].Session.State = "down"
			case "unknown lifecycle":
				input.interfaces[1].peerReads = append(input.interfaces[1].peerReads, store.IncidentPeerSessionMeasurement{TenantID: input.tenantID, ContextID: key.ContextID, RouterID: key.RouterID, SourceGeneration: 1, ObservedAt: first.ObservedAt})
			case "foreign route":
				route.Route.Source.TenantID = "foreign"
			}
			got, err := classifyIncidentVerdict(ctx, input, 16<<20)
			if name == "foreign route" {
				if !errors.Is(err, entity.ErrScopeMismatch) {
					t.Fatal("routing context crossed tenant scope", err)
				}
				return
			}
			want := incident.FaultUnknown
			if name == "complete" {
				want = incident.FaultWiderInternet
			}
			if err != nil || got.Domain != want {
				t.Fatal("routing error classification changed", got.Domain, want, err)
			}
			if name == "complete" {
				originals, routing := 0, 0
				for _, citation := range got.Hypotheses[2].For {
					if _, err := citation.SourceReference(); err != nil {
						t.Fatal("original namespace lost", err)
					}
					if citation.Routing != nil {
						routing++
						if citation.Routing.OriginASN != 64497 || citation.Routing.Sequence != "2" {
							t.Fatal("complete routing context changed")
						}
					}
					if citation.Reason == "complete_original_challenge_matched_external_no_route_errors" {
						originals++
					}
				}
				if originals != 2 || routing != 1 {
					t.Fatal("independent original errors or separate route provenance omitted", originals, routing)
				}
			}
		})
	}
}

func TestNativeInternetVerdictKeepsViewSequenceAndRedactsResponder(t *testing.T) {
	ctx, input := internetVerdictFixture(t)
	result, err := classifyIncidentVerdict(ctx, input, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	result.ContractVersion = "probectl.incident-verdict.v1"
	result.IncidentID = "b491e278-ad55-4bef-b915-dccce66d11e7"
	for i := range result.Hypotheses[2].For {
		if route := result.Hypotheses[2].For[i].Routing; route != nil {
			route.Sequence = "9223372036854775807"
		}
	}
	body, err := marshalNativeIncidentVerdict(result)
	if err != nil {
		t.Fatal(err)
	}
	redacted := ai.RedactTextForTenant(string(body), ai.DefaultRedaction, input.tenantID)
	var got incident.FaultVerdict
	if err := json.Unmarshal([]byte(redacted), &got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cite := range got.Hypotheses[2].For {
		if route := cite.Routing; route != nil {
			found = true
			if route.Sequence != "9223372036854775807" || route.ViewID != "aee337be-624f-440c-9be9-be3e2c19f7c5" || route.GenerationID != "bc646676-f577-4818-8b9a-59f9fa9f71ad" || route.OriginASN != 64497 || strings.Contains(route.Address, "198.18") || strings.Contains(route.Prefix, "198.18") {
				t.Fatal("native routing context narrowed sequence, lost lineage or disclosed responder")
			}
		}
	}
	if !found {
		t.Fatal("native response omitted selected routing context")
	}
}
