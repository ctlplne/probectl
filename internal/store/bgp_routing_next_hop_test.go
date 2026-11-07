// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func routingNextHopTestPeer(address string, asn uint32, id string) InterfaceRolePeerInput {
	at := time.Now().UTC()
	return InterfaceRolePeerInput{Address: netip.MustParseAddr(address), ASN: asn, SourceID: "evidence/" + id, InterfaceRoleEvidenceClock: InterfaceRoleEvidenceClock{ObservedAt: at, ValidUntil: at.Add(time.Hour)}}
}

func TestRoutingNextHopASRequiresActualUniqueNeighborAndCompleteProvenance(t *testing.T) {
	const first = "11111111-1111-4111-8111-111111111111"
	const second = "22222222-2222-4222-8222-222222222222"
	peer := routingNextHopTestPeer("2001:db8::1", 65010, first)
	path := routingChangeFixture()
	budget := entity.InterfaceRolePolicyBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20}
	fields, err := routingNextHopFields(t.Context(), []BGPRoutingChange{path, path}, []InterfaceRolePeerInput{peer}, budget)
	if err != nil || len(fields) != 2 || fields[0].ASN == nil || *fields[0].ASN != 65010 || fields[1].ASN == nil || *fields[1].ASN != 65010 || fields[0].Reason != "current_neighbor_observation" || !reflect.DeepEqual(fields[0].Sources, []string{peer.SourceID}) || !fields[0].ValidUntil.Equal(peer.ValidUntil) {
		t.Fatal("next-hop AS lost same-router neighbor identity or complete source evidence", fields, err)
	}
	fields[0].Sources[0] = "changed"
	if fields[1].Sources[0] != peer.SourceID {
		t.Fatal("one retained path mutated another path's provenance")
	}
	other := routingNextHopTestPeer("2001:db8::1", 65011, second)
	if got, err := routingNextHopFields(t.Context(), []BGPRoutingChange{path}, []InterfaceRolePeerInput{peer, other}, budget); err != nil || len(got) != 1 || got[0].ASN != nil || got[0].Sources != nil || got[0].Reason != "next_hop_as_conflict" {
		t.Fatal("conflicting current neighbors invented a next-hop AS", got, err)
	}
	other.ASN = peer.ASN
	other.ValidUntil = peer.ValidUntil.Add(-time.Minute)
	if got, err := routingNextHopFields(t.Context(), []BGPRoutingChange{path}, []InterfaceRolePeerInput{other, peer}, budget); err != nil || got[0].ASN == nil || len(got[0].Sources) != 2 || !got[0].ValidUntil.Equal(other.ValidUntil) {
		t.Fatal("agreeing sources lost complete provenance or earliest expiry", got, err)
	}
	// A route-server peer/path value does not identify the actual next hop.
	server := routingNextHopTestPeer("2001:db8::2", 65010, first)
	path.Segments = []BGPRoutingSegment{{Kind: 2, Values: []uint32{65010, 64500}}}
	for _, peers := range [][]InterfaceRolePeerInput{nil, {server}} {
		got, err := routingNextHopFields(t.Context(), []BGPRoutingChange{path}, peers, budget)
		if err != nil || len(got) != 1 || got[0].ASN != nil || got[0].Sources != nil {
			t.Fatal("next-hop AS was guessed from path or a different peer", got, err)
		}
	}
	path.NextHops = []netip.Addr{netip.MustParseAddr("fe80::1")}
	linkLocal := routingNextHopTestPeer("fe80::1", 65010, first)
	if got, err := routingNextHopFields(t.Context(), []BGPRoutingChange{path}, []InterfaceRolePeerInput{linkLocal}, budget); err != nil || got[0].ASN != nil {
		t.Fatal("unscoped link-local neighbor invented next-hop ownership", got, err)
	}
	mapped := routingChangeFixture()
	mapped.NextHops = []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")}
	v4 := routingNextHopTestPeer("192.0.2.1", 65010, first)
	if got, err := routingNextHopFields(t.Context(), []BGPRoutingChange{mapped}, []InterfaceRolePeerInput{v4}, budget); err != nil || got[0].ASN == nil || *got[0].ASN != 65010 || !mapped.NextHops[0].Is4In6() {
		t.Fatal("mapped next hop lost canonical association or its complete retained wire value", got, err)
	}
	side := BGPRoutingFlowSide{NextHops: fields}
	expireRoutingNextHopFields(&side, peer.ValidUntil)
	if side.NextHops[1].ASN != nil || side.NextHops[1].Sources != nil || side.NextHops[1].Reason != "expired_neighbor_observation" {
		t.Fatal("expired next-hop observation retained an ASN or provenance")
	}
}

func TestRoutingNextHopASRefusesLateMalformedUnadmittedAndForeignScope(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	peer := routingNextHopTestPeer("2001:db8::1", 65010, id)
	path := routingChangeFixture()
	budget := entity.InterfaceRolePolicyBudget{MemoryBytes: 8 << 20, WorkUnits: 8 << 20}
	for _, path := range []BGPRoutingChange{
		{NextHops: []netip.Addr{netip.MustParseAddr("2001:db8::2"), {}}},
		{NextHops: []netip.Addr{peer.Address, netip.MustParseAddr("fe80::1%eth0")}},
	} {
		if got, err := routingNextHopFields(t.Context(), []BGPRoutingChange{path}, []InterfaceRolePeerInput{peer}, budget); !errors.Is(err, entity.ErrInvalidClaim) || got != nil {
			t.Fatal("late malformed next hop escaped whole projection validation", got, err)
		}
	}
	for _, limited := range []entity.InterfaceRolePolicyBudget{{}, {MemoryBytes: 200, WorkUnits: 8 << 20}, {MemoryBytes: 8 << 20, WorkUnits: 1}} {
		if got, err := routingNextHopFields(t.Context(), []BGPRoutingChange{path}, []InterfaceRolePeerInput{peer}, limited); !errors.Is(err, entity.ErrInterfaceRoleBudget) || got != nil {
			t.Fatal("unadmitted neighbor lookup exposed partial ASN fields", got, err)
		}
	}
	peer.SourceID = "unproven"
	if got, err := routingNextHopFields(t.Context(), []BGPRoutingChange{path}, []InterfaceRolePeerInput{peer}, budget); !errors.Is(err, entity.ErrInvalidClaim) || got != nil {
		t.Fatal("unproven source reached next-hop projection", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := routingNextHopFields(ctx, []BGPRoutingChange{path}, nil, budget); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("canceled next-hop projection exposed partial state", err)
	}
	ctx = tenancy.WithTenant(t.Context(), tenancy.ID(id))
	for _, sc := range []tenancy.Scope{{}, {Tenant: tenancy.ID("foreign")}, {Tenant: tenancy.ID(id)}} {
		if got, err := (&InterfaceRoleInputsStore{}).RouterPeersInScope(ctx, sc, entity.Scope{TenantID: id, ContextID: id}, id, budget); !errors.Is(err, entity.ErrScopeMismatch) || got != nil {
			t.Fatal("router neighbor reader bypassed outer tenant boundary", err)
		}
	}
}
