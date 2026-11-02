// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSNMPSystemDescriptionIsBoundedMetadataOnConfiguredTargetOnly(t *testing.T) {
	now := time.Now().UTC()
	base := Observation{ID: uuid.NewString(),
		Source:    SourceKey{AgentID: "collector", Kind: DeviceTarget, SourceRef: "router.example"},
		Alias:     AliasKey{Kind: AddressAlias, Value: "192.0.2.1"},
		SourceRef: "snmp:configured-target", ObservedAt: now,
		SystemDescription: "router OS\r\nversion\t1"}
	if got, err := base.Normalize(now); err != nil || got.SystemDescription != base.SystemDescription {
		t.Fatalf("valid system metadata lost: %v", err)
	}
	for _, edit := range []func(*Observation){
		func(o *Observation) { o.Source.Kind = FlowExporter },
		func(o *Observation) { o.Alias.Kind = SNMPDeviceAlias; o.Alias.Value = "router-a" },
		func(o *Observation) { o.SourceRef = "snmp:ifIndex:7" },
		func(o *Observation) { o.SystemDescription = "bad\x1bvalue" },
		func(o *Observation) { o.SystemDescription = string([]byte{0xff}) },
		func(o *Observation) { o.SystemDescription = strings.Repeat("x", 1025) },
	} {
		bad := base
		edit(&bad)
		if _, err := bad.Normalize(now); err == nil {
			t.Fatal("untrusted or wrong-family system metadata was accepted")
		}
	}
}

func TestBMPObservationRequiresExactBoundedOriginSerial(t *testing.T) {
	now := time.Now().UTC()
	base := Observation{ID: uuid.NewString(),
		Source:    SourceKey{AgentID: "listener", Kind: BMPPeer, SourceRef: "router"},
		Alias:     AliasKey{Kind: AddressAlias, Value: "192.0.2.7"},
		SourceRef: "bmp:router:router:peer-asn:64500", ObservedAt: now,
		OriginSerial: "ab1234"}
	if _, err := base.Normalize(now); err != nil {
		t.Fatal(err)
	}
	for _, serial := range []string{"", "AB1234", "ab:12", "x", "ab\n12"} {
		bad := base
		bad.OriginSerial = serial
		if _, err := bad.Normalize(now); err == nil {
			t.Fatalf("BMP origin serial %q accepted", serial)
		}
	}
	other := base
	other.Source.Kind = DeviceTarget
	if _, err := other.Normalize(now); err == nil {
		t.Fatal("non-BMP source smuggled a router certificate serial")
	}
}

func TestSNMPInterfaceObservationKeepsOnlyBoundedLabels(t *testing.T) {
	now := time.Now().UTC()
	item := Observation{ID: uuid.NewString(),
		Source:    SourceKey{AgentID: "collector", Kind: DeviceTarget, SourceRef: "192.0.2.1"},
		Alias:     AliasKey{Kind: SNMPInterfaceAlias, Value: "4294967295"},
		SourceRef: "snmp:ifIndex:4294967295", ObservedAt: now,
		InterfaceName: "xe-0/0/7", InterfaceDescription: "uplink"}
	if _, err := item.Normalize(now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Observation){
		func(o *Observation) { o.InterfaceName = "bad\nname" },
		func(o *Observation) { o.SourceRef = "snmp:ifIndex:7" },
		func(o *Observation) { o.InterfaceDescription = strings.Repeat("a", 1025) },
		func(o *Observation) { o.Source.Kind = FlowExporter },
		func(o *Observation) { o.Alias.Kind = AddressAlias; o.Alias.Value = "192.0.2.1" },
	} {
		bad := item
		mutate(&bad)
		if _, err := bad.Normalize(now); err == nil {
			t.Fatalf("malformed interface evidence accepted: %+v", bad)
		}
	}
}

func TestPhysicalNeighborObservationKeepsOriginalPortsWithoutChoosingContext(t *testing.T) {
	now := time.Now().UTC()
	item := Observation{ID: uuid.NewString(),
		Source:    SourceKey{AgentID: "collector", Kind: DeviceTarget, SourceRef: "192.0.2.1"},
		Alias:     AliasKey{Kind: PhysicalNeighborAlias, Value: "neighbor:abc123"},
		SourceRef: "neighbor:abc123", ObservedAt: now,
		NeighborProtocol: "lldp", NeighborLocalIfIndex: 4294967295,
		NeighborLocalPortID: "Ethernet7", NeighborRemotePortID: "Ethernet8",
		NeighborChassisID: "00:11:22:33:44:55", NeighborDeviceName: "edge-b",
		NeighborAddress: "::ffff:192.0.2.2"}
	got, err := item.Normalize(now)
	if err != nil || got.NeighborAddress != "192.0.2.2" {
		t.Fatalf("valid neighbor claim = %+v, %v", got, err)
	}
	for _, mutate := range []func(*Observation){
		func(o *Observation) { o.Source.Kind = FlowExporter },
		func(o *Observation) { o.Alias.Value = "neighbor:other" },
		func(o *Observation) { o.NeighborLocalIfIndex = 0 },
		func(o *Observation) { o.NeighborProtocol = "made-up" },
		func(o *Observation) { o.NeighborRemotePortID = "" },
		func(o *Observation) { o.NeighborLocalPortID = "bad\nport" },
		func(o *Observation) { o.NeighborAddress = "fe80::1%eth0" },
		func(o *Observation) { o.Alias.Kind = AddressAlias; o.Alias.Value = "192.0.2.2" },
	} {
		bad := item
		mutate(&bad)
		if _, err := bad.Normalize(now); err == nil {
			t.Fatalf("malformed physical neighbor accepted: %+v", bad)
		}
	}
}

func TestEvidenceSourceCannotClaimAnotherPlaneAlias(t *testing.T) {
	now := time.Now().UTC()
	base := Observation{ID: uuid.NewString(),
		Source:    SourceKey{AgentID: "collector", Kind: DeviceTarget, SourceRef: "192.0.2.1"},
		Alias:     AliasKey{Kind: AddressAlias, Value: "192.0.2.1"},
		SourceRef: "observed:address", ObservedAt: now}
	for _, tc := range []struct {
		source SourceKind
		alias  AliasKind
	}{
		{DeviceTarget, FlowExporterAlias},
		{DeviceTarget, AgentSiteAlias},
		{FlowExporter, SNMPDeviceAlias},
		{FlowExporter, PhysicalNeighborAlias},
		{BMPPeer, SNMPInterfaceAlias},
		{BMPPeer, AgentSiteAlias},
		{PathAgent, FlowExporterAlias},
		{AgentSite, AddressAlias},
	} {
		claim := base
		claim.Source.Kind, claim.Alias.Kind = tc.source, tc.alias
		if tc.alias == SNMPInterfaceAlias {
			claim.Alias.Value = "1"
		}
		if tc.source == BMPPeer {
			claim.OriginSerial = "ab1234"
		}
		if _, err := claim.Normalize(now); err != ErrInvalidClaim {
			t.Fatalf("%s source claimed %s alias: %v", tc.source, tc.alias, err)
		}
	}
}

func TestFlowEvidenceCannotNameAnotherExporter(t *testing.T) {
	now := time.Now().UTC()
	base := Observation{ID: uuid.NewString(),
		Source:    SourceKey{AgentID: "collector", Kind: FlowExporter, SourceRef: "192.0.2.7"},
		Alias:     AliasKey{Kind: AddressAlias, Value: "192.0.2.7"},
		SourceRef: "flow:ipfix:domain:99", ObservedAt: now}
	if _, err := base.Normalize(now); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []AliasKey{
		{Kind: AddressAlias, Value: "192.0.2.8"},
		{Kind: FlowExporterAlias, Value: "192.0.2.8/ipfix/99"},
		{Kind: FlowExporterAlias, Value: "192.0.2.7/unknown/99"},
		{Kind: FlowExporterAlias, Value: "192.0.2.7/ipfix/4294967296"},
	} {
		claim := base
		claim.Alias = alias
		if _, err := claim.Normalize(now); err != ErrInvalidClaim {
			t.Fatalf("flow source claimed unrelated exporter alias %+v: %v", alias, err)
		}
	}
	base.Alias = AliasKey{Kind: FlowExporterAlias, Value: "192.0.2.7/ipfix/99"}
	if _, err := base.Normalize(now); err != nil {
		t.Fatalf("real flow alias refused: %v", err)
	}
	base.SourceRef = "flow:netflow9:domain:99"
	if _, err := base.Normalize(now); err != ErrInvalidClaim {
		t.Fatalf("flow alias/provenance mismatch accepted: %v", err)
	}
}

func TestBMPPeerEvidenceBindsRouterAndPeerASN(t *testing.T) {
	now := time.Now().UTC()
	base := Observation{ID: uuid.NewString(),
		Source:    SourceKey{AgentID: "listener", Kind: BMPPeer, SourceRef: "router"},
		Alias:     AliasKey{Kind: BMPPeerAlias, Value: "192.0.2.7/as64500"},
		SourceRef: "bmp:router:router:peer-asn:64500", OriginSerial: "ab1234", ObservedAt: now}
	if _, err := base.Normalize(now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Observation){
		func(o *Observation) { o.SourceRef = "bmp:router:other:peer-asn:64500" },
		func(o *Observation) { o.Alias.Value = "192.0.2.7/as64501" },
		func(o *Observation) { o.Alias.Value = "192.0.2.7/as4294967296" },
		func(o *Observation) { o.Alias.Value = "invalid/as64500" },
	} {
		claim := base
		mutate(&claim)
		if _, err := claim.Normalize(now); err != ErrInvalidClaim {
			t.Fatalf("forged BMP peer shape accepted: %+v: %v", claim, err)
		}
	}
}

func TestAgentSiteEvidenceUsesOnlyOwnAgentLabel(t *testing.T) {
	now := time.Now().UTC()
	base := Observation{ID: uuid.NewString(),
		Source:    SourceKey{AgentID: "agent-a", Kind: AgentSite, SourceRef: "agent-a"},
		Alias:     AliasKey{Kind: AgentSiteAlias, Value: "west-dc"},
		SourceRef: "agent:label:site", ObservedAt: now}
	if _, err := base.Normalize(now); err != nil {
		t.Fatal(err)
	}
	base.Source.SourceRef = "agent-b"
	if _, err := base.Normalize(now); err != ErrInvalidClaim {
		t.Fatalf("site evidence claimed another agent source: %v", err)
	}
}
