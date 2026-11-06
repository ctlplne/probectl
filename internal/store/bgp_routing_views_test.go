// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func routingViewFixture() BGPRoutingViewDefinition {
	// Complete OPEN carrying the full four-AS capability; this is constructed
	// protocol metadata, not an authenticated real-router receipt.
	open := append(bytes.Repeat([]byte{255}, 16), 0, 37, 1, 4, 0x5b, 0xa0, 0, 90, 192, 0, 2, 9, 8, 2, 6, 65, 4, 255, 255, 255, 255)
	return BGPRoutingViewDefinition{Kind: "adj_rib_in_pre_policy", AFI: 1, SAFI: 1, Peer: BGPRoutingPeer{
		Type: 0, Address: netip.MustParseAddr("192.0.2.12"), ASN: math.MaxUint32, BGPIdentifier: netip.MustParseAddr("192.0.2.9"),
		LocalAddress: netip.MustParseAddr("192.0.2.11"), LocalPort: 179, RemotePort: 65535,
		SentOpen: bytes.Clone(open), ReceivedOpen: bytes.Clone(open),
		Information: []BGPRoutingPeerInformation{{Type: 65535, Value: []byte{0, 255, 1}}, {Type: 65535, Value: []byte{}}, {Type: 0, Value: nil}},
	}}
}

func routingViewBudget() BGPRoutingBudget {
	return BGPRoutingBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20, StateBytes: 64 << 20}
}

func TestBGPRoutingViewMetadataKeepsStablePeerSlotsAndCompleteValues(t *testing.T) {
	input := routingViewFixture()
	body, key, err := routingViewMetadata(t.Context(), input, routingViewBudget())
	if err != nil || key == ([32]byte{}) {
		t.Fatal("whole route view metadata refused", err)
	}
	var owned BGPRoutingPeer
	if err := json.Unmarshal(body, &owned); err != nil {
		t.Fatal(err)
	}
	if owned.ASN != math.MaxUint32 || owned.RemotePort != 65535 || len(owned.Information) != 3 ||
		owned.Information[0].Type != 65535 || !bytes.Equal(owned.Information[0].Value, []byte{0, 255, 1}) ||
		owned.Information[1].Value == nil || owned.Information[2].Value != nil || !bytes.Equal(owned.SentOpen, input.Peer.SentOpen) {
		t.Fatal("whole route view lost full values, repeated information or presence")
	}
	input.Peer.SentOpen[0] = 0
	input.Peer.Information[0].Value[0] = 2
	if owned.SentOpen[0] != 255 || owned.Information[0].Value[0] != 0 {
		t.Fatal("route view metadata aliases caller input")
	}
	input = routingViewFixture()
	input.Peer.ASN, input.Peer.BGPIdentifier = 64496, netip.MustParseAddr("198.51.100.9")
	_, restarted, err := routingViewMetadata(t.Context(), input, routingViewBudget())
	if err != nil || restarted != key {
		t.Fatal("changed peer ASN/id escaped its logical restart slot", err)
	}
	for _, change := range []func(*BGPRoutingViewDefinition){
		func(d *BGPRoutingViewDefinition) { d.Peer.Address = netip.MustParseAddr("::ffff:192.0.2.12") },
		func(d *BGPRoutingViewDefinition) { d.Peer.Address = netip.MustParseAddr("192.0.2.13") },
		func(d *BGPRoutingViewDefinition) { d.Peer.Distinguisher[7] = 1 },
	} {
		other := routingViewFixture()
		change(&other)
		_, candidate, err := routingViewMetadata(t.Context(), other, routingViewBudget())
		if err != nil || candidate == key {
			t.Fatal("distinct routing peer/family/distinguisher collapsed", err)
		}
	}
	loc := routingViewFixture()
	loc.Kind = "loc_rib"
	loc.Peer.Type = 3
	loc.Peer.Address = netip.Addr{}
	loc.Peer.LocalAddress = netip.Addr{}
	loc.Peer.LocalPort = 0
	loc.Peer.RemotePort = 0
	_, first, err := routingViewMetadata(t.Context(), loc, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	loc.Peer.ASN = 64497
	loc.Peer.BGPIdentifier = netip.MustParseAddr("198.51.100.7")
	_, second, err := routingViewMetadata(t.Context(), loc, routingViewBudget())
	if err != nil || first != second {
		t.Fatal("Loc-RIB router restart created an unrelated peer slot", err)
	}
}

func TestBGPRoutingViewMetadataRefusesIncompleteShapeAndWholeAdmission(t *testing.T) {
	for _, change := range []func(*BGPRoutingViewDefinition){
		func(d *BGPRoutingViewDefinition) { d.AFI = 0 },
		func(d *BGPRoutingViewDefinition) { d.SAFI = 0 },
		func(d *BGPRoutingViewDefinition) { d.Kind = "public_bgp" },
		func(d *BGPRoutingViewDefinition) { d.Peer.Type = 4 },
		func(d *BGPRoutingViewDefinition) { d.Peer.BGPIdentifier = netip.Addr{} },
		func(d *BGPRoutingViewDefinition) { d.Peer.SentOpen = nil },
		func(d *BGPRoutingViewDefinition) { d.Peer.ReceivedOpen = nil },
		func(d *BGPRoutingViewDefinition) { d.Peer.Address = netip.Addr{} },
		func(d *BGPRoutingViewDefinition) { d.Filtered = true },
		func(d *BGPRoutingViewDefinition) { d.Kind = "loc_rib" },
	} {
		input := routingViewFixture()
		change(&input)
		body, key, err := routingViewMetadata(t.Context(), input, routingViewBudget())
		if !errors.Is(err, ErrBGPRoutingView) || body != nil || key != ([32]byte{}) {
			t.Fatal("incomplete route view returned partial identity", err)
		}
	}
	for _, budget := range []BGPRoutingBudget{{}, {MemoryBytes: 1024, WorkUnits: 1, StateBytes: 1}, {MemoryBytes: 8 << 20, WorkUnits: 1, StateBytes: 1}} {
		body, key, err := routingViewMetadata(t.Context(), routingViewFixture(), budget)
		if !errors.Is(err, ErrBGPRoutingBudget) || body != nil || key != ([32]byte{}) {
			t.Fatal("routing metadata escaped whole admission", err)
		}
	}
	input := routingViewFixture()
	input.Peer.Information = make([]BGPRoutingPeerInformation, 100)
	budget := routingViewBudget()
	budget.WorkUnits = 1024
	if body, key, err := routingViewMetadata(t.Context(), input, budget); !errors.Is(err, ErrBGPRoutingBudget) || body != nil || key != ([32]byte{}) {
		t.Fatal("empty repeated information escaped routing work admission", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if body, key, err := routingViewMetadata(canceled, routingViewFixture(), routingViewBudget()); !errors.Is(err, context.Canceled) || body != nil || key != ([32]byte{}) {
		t.Fatal("canceled route view returned partial identity", err)
	}
}

func TestBGPRoutingBeginRefusesForeignTenantBeforeMetadataOrStorage(t *testing.T) {
	tenant := "11111111-1111-4111-8111-111111111111"
	source := BGPRoutingSource{Scope: entity.Scope{TenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ContextID: "22222222-2222-4222-8222-222222222222"}}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	view, err := (BGPRouting{}).beginViewInScope(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}, source, BGPRoutingViewDefinition{}, source.ObservedAt, routingViewBudget())
	if !errors.Is(err, entity.ErrScopeMismatch) || view.ID != "" || view.Generation != "" {
		t.Fatal("foreign routing generation reached metadata or storage", err)
	}
}
