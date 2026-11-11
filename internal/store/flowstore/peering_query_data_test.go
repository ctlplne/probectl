// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func peeringQueryFixture(t *testing.T, tenant string, at time.Time, count int) (PeeringQueryTarget, []RoutingProjection, Row) {
	t.Helper()
	target := PeeringQueryTarget{Scope: entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}, RouterID: "33333333-3333-4333-8333-333333333333", PeerASN: ^uint32(0), Direction: "inbound"}
	fields := map[string]string{}
	for _, side := range []string{"src", "dst"} {
		fields[side+"_bgp_provenance"] = "router_selected"
		fields[side+"_bgp_prefix"] = "203.0.113.0/24"
		fields[side+"_bgp_as_paths"] = `["64500 4294967295"]`
		fields[side+"_bgp_origin_as"] = "4294967295"
		fields[side+"_bgp_first_transit_as"] = "64500"
		fields[side+"_bgp_next_hop_as"] = ""
		fields[side+"_bgp_rpki"] = "unknown"
	}
	fields["dst_bgp_as_paths"], fields["dst_bgp_origin_as"] = `["64501"]`, "64501"
	fields["dst_bgp_first_transit_as"] = ""
	input := entity.FlowCaptureInput{Exporter: netip.MustParseAddr("192.0.2.1"), Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("2001:db8::1"), Protocol: "ipfix", Domain: ^uint32(0)}
	rows := make([]RoutingProjection, count)
	var last Row
	for i := range rows {
		var raw [32]byte
		binary.BigEndian.PutUint64(raw[:8], uint64(i+1))
		key, err := entity.FlowCaptureKey(tenant, "routing-flow", raw, input)
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = RoutingProjection{Scope: target.Scope, Key: key, Clock: at.UnixNano(), Fields: fields, SourceIDs: []string{"routing-view/original-source"}, FactsID: [32]byte{31: 1}, Peering: &PeeringRoutingMatch{RouterID: target.RouterID, PeerASN: target.PeerASN, Source: "eligible", Destination: "not_on_path"}}
		last = Row{TenantID: tenant, AgentID: "routing-flow", Exporter: input.Exporter.String(), SrcAddr: input.Source.String(), DstAddr: input.Destination.String(), Protocol: input.Protocol, ObsDomain: input.Domain, RawFlowDigest: hex.EncodeToString(raw[:]), RoutingCaptureKey: hex.EncodeToString(key[:]), RoutingCapturedUnixNanos: at.UnixNano()}
	}
	return target, rows, last
}

func TestPeeringQueryDataBindsCompleteReferencesTargetDirectionAndImmutableStates(t *testing.T) {
	at := time.Unix(1700000000, 123456789).UTC()
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		target, rows, last := peeringQueryFixture(t, tenant, at, 50_001)
		data, err := NewPeeringQueryData(ctx, target, at, rows, 512<<20)
		if err != nil || data == nil || len(data.states) != len(rows) || data.stateForRow(last) != "eligible" {
			t.Fatal("peering query data truncated original references or lost its last exact match", err)
		}
		digest, err := data.Digest(ctx, tenant)
		if err != nil || len(digest) != 64 {
			t.Fatal("peering operation identity is unavailable", digest, err)
		}
		reversed := slices.Clone(rows)
		slices.Reverse(reversed)
		reordered, err := NewPeeringQueryData(ctx, target, at.Add(time.Second), reversed, 512<<20)
		if err != nil || reordered.digest != digest {
			t.Fatal("peering identity depends on order or an advancing read clock", err)
		}
		other := target
		other.Direction = "outbound"
		outbound, err := NewPeeringQueryData(ctx, other, at, rows, 512<<20)
		if err != nil || outbound.digest == digest || outbound.stateForRow(last) != "not_on_path" {
			t.Fatal("peering operation reused the other traffic direction", err)
		}
		for _, row := range []*RoutingProjection{&rows[0], &rows[len(rows)-1]} {
			row.Peering.Source = "ambiguous"
		}
		if data.stateForRow(last) != "eligible" || data.digest != digest {
			t.Fatal("caller mutated admitted peering states or publication identity")
		}
		if got, err := NewPeeringQueryData(ctx, target, at, rows, 512<<20); !errors.Is(err, ErrRoutingQueryScope) || got != nil {
			t.Fatal("same original fact silently reused inconsistent peering states", err)
		}
		foreign := last
		foreign.TenantID = "99999999-9999-4999-8999-999999999999"
		if data.stateForRow(foreign) != "unavailable" {
			t.Fatal("foreign flow row reused private peering state")
		}
		stale := last
		stale.RoutingCapturedUnixNanos++
		if data.stateForRow(stale) != "unavailable" {
			t.Fatal("peering lookup replaced an original capture clock")
		}
	}
}

func TestPeeringQueryDataRefusesMixedUnprovenAndUnadmittedInputs(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	at := time.Unix(1700000000, 0).UTC()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	target, rows, _ := peeringQueryFixture(t, tenant, at, 2)
	for _, change := range []func(*RoutingProjection){
		func(row *RoutingProjection) { row.TenantID = "66666666-6666-4666-8666-666666666666" },
		func(row *RoutingProjection) {
			row.ContextID = "99999999-9999-4999-8999-999999999999"
			row.FactsID = [32]byte{}
		},
		func(row *RoutingProjection) { row.Peering = nil },
		func(row *RoutingProjection) { row.Peering.PeerASN-- },
		func(row *RoutingProjection) { row.Peering.Source = "assumed" },
	} {
		changed := slices.Clone(rows)
		match := *rows[1].Peering
		changed[1].Peering = &match
		change(&changed[1])
		if got, err := NewPeeringQueryData(ctx, target, at, changed, 1<<20); !errors.Is(err, ErrRoutingQueryScope) || got != nil {
			t.Fatal("peering query accepted a mixed target or unproven late state", err)
		}
	}
	foreign := target
	foreign.TenantID = "66666666-6666-4666-8666-666666666666"
	if got, err := NewPeeringQueryData(ctx, foreign, at, rows, 0); !errors.Is(err, ErrRoutingQueryScope) || got != nil {
		t.Fatal("peering target admission preceded the tenant boundary", err)
	}
	if got, err := NewPeeringQueryData(ctx, target, at, rows, 4096); !errors.Is(err, ErrExplorerBudget) || got != nil {
		t.Fatal("peering query returned partial unadmitted state", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := NewPeeringQueryData(canceled, target, at, rows, 1<<20); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("canceled peering input returned an operation", err)
	}
}

func TestPeeringQueryDigestIncludesOriginalStatesAndTargetPeer(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	at := time.Unix(1700000000, 0).UTC()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	target, rows, _ := peeringQueryFixture(t, tenant, at, 1)
	before, err := NewPeeringQueryData(ctx, target, at, rows, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	rows[0].Peering.Source = "ambiguous"
	after, err := NewPeeringQueryData(ctx, target, at, rows, 1<<20)
	if err != nil || before.routing.digest != after.routing.digest || before.digest == after.digest {
		t.Fatal("peering digest omitted an original state or target peer", err)
	}
	target.PeerASN, rows[0].Peering.PeerASN = 64500, 64500
	other, err := NewPeeringQueryData(ctx, target, at, rows, 1<<20)
	if err != nil || after.routing.digest != other.routing.digest || after.digest == other.digest {
		t.Fatal("peering digest omitted an original state or target peer", err)
	}
}
