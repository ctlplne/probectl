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
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func publicRoutingMetadataFixture() BGPRoutingViewDefinition {
	maximum, zero, clock := ^uint32(0), uint32(0), int64(1700000000123456789)
	return BGPRoutingViewDefinition{Kind: "public_bgp", AFI: 2, SAFI: 1, Public: &BGPPublicRoutingPeer{
		Feed: "ris", Format: "mrt_table_dump_v2", Collector: "rrc00", PeerAddress: netip.MustParseAddr("::ffff:192.0.2.1"), PeerASN: maximum,
		PeerBGPIdentifier: &zero, CollectorIdentifier: &maximum, ViewName: []byte{}, ObservedUnixNanos: &clock, Cursor: "4294967295",
	}}
}

func TestPublicRoutingMetadataKeepsWholeSourceIdentityWithoutInventedBMP(t *testing.T) {
	definition := publicRoutingMetadataFixture()
	definition.Public.ViewName = bytes.Repeat([]byte{0, 255, 17, 12}, 500_001)
	budget := BGPRoutingBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, StateBytes: 16 << 20}
	body, key, err := routingViewMetadata(t.Context(), definition, budget)
	if err != nil || len(body) < 2<<20 || key == ([32]byte{}) {
		t.Fatal("complete public source metadata was refused or lost its peer identity", len(body), err)
	}
	var stored BGPPublicRoutingPeer
	if err := json.Unmarshal(body, &stored); err != nil || stored.PeerASN != ^uint32(0) || stored.PeerAddress != definition.Public.PeerAddress || stored.PeerBGPIdentifier == nil || *stored.PeerBGPIdentifier != 0 || stored.CollectorIdentifier == nil || *stored.CollectorIdentifier != ^uint32(0) || stored.ObservedUnixNanos == nil || *stored.ObservedUnixNanos != *definition.Public.ObservedUnixNanos || !bytes.Equal(stored.ViewName, definition.Public.ViewName) {
		t.Fatal("public metadata lost source widths, exact clock, family or full binary view", err)
	}
	definition.Public.ViewName[0] = 99
	if stored.ViewName[0] != 0 {
		t.Fatal("public metadata retained mutable caller bytes")
	}
	definition.Public.ViewName[0] = 0
	changedClock := int64(1700000000987654321)
	definition.Public.ObservedUnixNanos, definition.Public.Cursor = &changedClock, "next-source-cursor"
	changed, same, err := routingViewMetadata(t.Context(), definition, budget)
	if err != nil || same != key || bytes.Equal(changed, body) {
		t.Fatal("public source clock or cursor changed the peer slot or vanished from retry metadata", err)
	}
	definition.Public.PeerBGPIdentifier = nil
	if _, other, err := routingViewMetadata(t.Context(), definition, budget); err != nil || other == key {
		t.Fatal("absent public peer identifier aliased an explicitly observed zero", err)
	}
	definition = publicRoutingMetadataFixture()
	withEmpty, emptyKey, err := routingViewMetadata(t.Context(), definition, budget)
	if err != nil {
		t.Fatal(err)
	}
	definition.Public.ViewName = nil
	withAbsent, absentKey, err := routingViewMetadata(t.Context(), definition, budget)
	if err != nil || emptyKey == absentKey || bytes.Equal(withEmpty, withAbsent) {
		t.Fatal("empty MRT view name was replaced by unavailable metadata", err)
	}
	legacy, err := json.Marshal(BGPRoutingViewDefinition{Kind: "loc_rib"})
	if err != nil || bytes.Contains(legacy, []byte(`"public"`)) {
		t.Fatal("absent public metadata changed the existing BMP serialized shape", err)
	}
}

func TestPublicRoutingMetadataRefusesMixedViewsAndCannotGrantRouterWrites(t *testing.T) {
	budget := BGPRoutingBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, StateBytes: 16 << 20}
	for _, mutate := range []func(*BGPRoutingViewDefinition){
		func(d *BGPRoutingViewDefinition) { d.Public = nil },
		func(d *BGPRoutingViewDefinition) { d.Kind = "loc_rib" },
		func(d *BGPRoutingViewDefinition) { d.AFI = 3 },
		func(d *BGPRoutingViewDefinition) { d.Peer.SentOpen = []byte{255} },
		func(d *BGPRoutingViewDefinition) { d.Peer.ASN = 64500 },
		func(d *BGPRoutingViewDefinition) { d.Public.Feed = "unknown" },
		func(d *BGPRoutingViewDefinition) { d.Public.Format = "unknown" },
		func(d *BGPRoutingViewDefinition) { d.Public.Collector = "" },
		func(d *BGPRoutingViewDefinition) { d.Public.Collector = string([]byte{255}) },
		func(d *BGPRoutingViewDefinition) { d.Public.PeerASN = 0 },
		func(d *BGPRoutingViewDefinition) { d.Public.PeerAddress = netip.MustParseAddr("fe80::1%en0") },
		func(d *BGPRoutingViewDefinition) { d.Public.Feed, d.Public.Format = "routeviews", "ris_live" },
	} {
		definition := publicRoutingMetadataFixture()
		mutate(&definition)
		if body, key, err := routingViewMetadata(t.Context(), definition, budget); err == nil || body != nil || key != ([32]byte{}) {
			t.Fatal("public routing metadata admitted a mixed or invalid view", err)
		}
	}
	definition := publicRoutingMetadataFixture()
	for _, limited := range []BGPRoutingBudget{{MemoryBytes: 1, WorkUnits: 1 << 20, StateBytes: 1 << 20}, {MemoryBytes: 1 << 20, WorkUnits: 1, StateBytes: 1 << 20}, {MemoryBytes: 1 << 20, WorkUnits: 1 << 20, StateBytes: 1}} {
		if body, key, err := routingViewMetadata(t.Context(), definition, limited); !errors.Is(err, ErrBGPRoutingBudget) || body != nil || key != ([32]byte{}) {
			t.Fatal("public metadata returned a partial admission prefix", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if body, _, err := routingViewMetadata(ctx, definition, budget); !errors.Is(err, context.Canceled) || body != nil {
		t.Fatal("public metadata ignored cancellation", err)
	}
	const tenant = "11111111-1111-4111-8111-111111111111"
	source := BGPRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}, RouterID: "33333333-3333-4333-8333-333333333333", CollectorAgentID: "collector", SourceRef: "origin", SenderSerial: "issued", OriginSerial: "origin-issued", ObservedAt: time.Now()}
	ctx = tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	if view, err := (BGPRouting{}).beginViewInScope(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}, source, definition, time.Now().Add(time.Minute), budget); !errors.Is(err, ErrBGPRoutingView) || view.ID != "" {
		t.Fatal("public metadata acquired the BMP router writer without its separate source authority", err)
	}
}
