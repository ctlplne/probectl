// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func routingLookupDefinition(afi uint16) BGPRoutingViewDefinition {
	d := routingViewFixture()
	d.Kind = "loc_rib"
	d.AFI = afi
	d.Peer.Type = 3
	d.Peer.Address = netip.Addr{}
	d.Peer.LocalAddress = netip.Addr{}
	d.Peer.LocalPort = 0
	d.Peer.RemotePort = 0
	return d
}
func routingLookupBegin(t *testing.T, f *roleInputsFixture, source BGPRoutingSource, d BGPRoutingViewDefinition) BGPRoutingViewRef {
	t.Helper()
	var view BGPRoutingView
	err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		view, err = (BGPRouting{}).beginViewInScope(ctx, sc, source, d, source.ObservedAt.Add(5*time.Minute), routingViewBudget())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return BGPRoutingViewRef{ID: view.ID, Generation: view.Generation}
}
func routingLookupRead(t *testing.T, f *roleInputsFixture, source BGPRoutingSource, ref BGPRoutingViewRef, address string, budget BGPRoutingBudget) (routingLookup, error) {
	t.Helper()
	var got routingLookup
	err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		got, err = (BGPRouting{}).lookupViewInScope(ctx, sc, source, ref, netip.MustParseAddr(address), budget)
		return err
	})
	return got, err
}
func routingLookupApply(t *testing.T, f *roleInputsFixture, source BGPRoutingSource, ref BGPRoutingViewRef, batch BGPRoutingBatch) {
	t.Helper()
	batch.ObservedAt = routingFixtureTime(f)
	result, err := routingFixtureApply(t, f, source, ref, batch, routingViewBudget())
	if err != nil || result.Status != "applied" {
		t.Fatal("lookup fixture batch refused", result, err)
	}
}

func TestBGPRoutingLookupKeepsLongestPrefixEveryPathTenantFamilyAndSelectedView(t *testing.T) {
	f := newRoleInputsFixture(t)
	sources := []BGPRoutingSource{routingFixtureSource(f, 0), routingFixtureSource(f, 1)}
	for _, afi := range []uint16{1, 2} {
		refs := []BGPRoutingViewRef{routingLookupBegin(t, f, sources[0], routingLookupDefinition(afi)), routingLookupBegin(t, f, sources[1], routingLookupDefinition(afi))}
		f.in(sources[1].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET id=$2,generation=$3 WHERE tenant_id=$1 AND id=$4 AND generation=$5`, sources[1].TenantID, refs[0].ID, refs[0].Generation, refs[1].ID, refs[1].Generation)
			return err
		})
		refs[1] = refs[0]
		prefixes := []string{"0.0.0.0/0", "10.0.0.0/8", "10.42.7.0/24"}
		targets := []string{"203.0.113.1", "10.43.0.1", "10.42.7.19"}
		if afi == 2 {
			prefixes = []string{"::/0", "2001:db8::/32", "2001:db8:7::/48"}
			targets = []string{"2001:db9::1", "2001:db8:8::1", "2001:db8:7::19"}
		}
		expected := make([][]BGPRoutingChange, 2)
		for lane, source := range sources {
			batch := BGPRoutingBatch{Sequence: 1, AFI: afi, SAFI: 1}
			for n, prefix := range prefixes {
				paths := []struct {
					has bool
					id  uint32
				}{{false, 0}}
				if n == 2 {
					paths = append(paths, struct {
						has bool
						id  uint32
					}{true, 0}, struct {
						has bool
						id  uint32
					}{true, math.MaxUint32})
				}
				for _, path := range paths {
					change := routingChangeFixture()
					change.Prefix = netip.MustParsePrefix(prefix)
					change.HasPathID, change.PathID = path.has, path.id
					change.Segments[1].Values[0] = uint32(64496 + lane)
					batch.Changes = append(batch.Changes, change)
					if n == 2 {
						expected[lane] = append(expected[lane], change)
					}
				}
			}
			routingLookupApply(t, f, source, refs[lane], batch)
			if got, err := routingLookupRead(t, f, source, refs[lane], targets[2], routingViewBudget()); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
				t.Fatal("staging route became a complete lookup", got, err)
			}
			routingLookupApply(t, f, source, refs[lane], BGPRoutingBatch{Sequence: 2, AFI: afi, SAFI: 1, EndOfRIB: true})
		}
		for lane, source := range sources {
			for n, target := range targets {
				got, err := routingLookupRead(t, f, source, refs[lane], target, routingViewBudget())
				if err != nil || got.Prefix.String() != prefixes[n] || got.Source.TenantID != source.TenantID || got.View != refs[lane] || got.LastSequence != 2 || !got.ValidUntil.After(got.AsOf) {
					t.Fatal("complete routing lookup lost selected tenant/family/longest prefix", got.Prefix, err)
				}
				if n == 2 && !reflect.DeepEqual(got.Paths, expected[lane]) {
					t.Fatal("routing lookup lost complete path identity or mixed tenants", got.Paths)
				}
			}
		}
		small := routingViewBudget()
		small.MemoryBytes = 16 << 10
		if got, err := routingLookupRead(t, f, sources[0], refs[0], targets[2], small); !errors.Is(err, ErrBGPRoutingBudget) || got.Paths != nil {
			t.Fatal("whole routing lookup returned partial over-budget paths", got, err)
		}
		withdraw := BGPRoutingBatch{Sequence: 3, AFI: afi, SAFI: 1}
		for _, change := range expected[0] {
			withdraw.Changes = append(withdraw.Changes, BGPRoutingChange{Prefix: change.Prefix, HasPathID: change.HasPathID, PathID: change.PathID, Withdraw: true})
		}
		routingLookupApply(t, f, sources[0], refs[0], withdraw)
		got, err := routingLookupRead(t, f, sources[0], refs[0], targets[2], routingViewBudget())
		if err != nil || got.Prefix.String() != prefixes[1] || len(got.Paths) != 1 {
			t.Fatal("withdrawn longest prefix retained former paths", got.Prefix, err)
		}
		sibling, err := routingLookupRead(t, f, sources[1], refs[1], targets[2], routingViewBudget())
		if err != nil || !reflect.DeepEqual(sibling.Paths, expected[1]) {
			t.Fatal("withdrawal changed sibling routing paths", err)
		}
	}
	adjacent := routingFixtureBegin(t, f, sources[0])
	routingLookupApply(t, f, sources[0], adjacent, BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, Changes: []BGPRoutingChange{routingChangeFixture()}})
	routingLookupApply(t, f, sources[0], adjacent, BGPRoutingBatch{Sequence: 2, AFI: 1, SAFI: 1, EndOfRIB: true})
	if got, err := routingLookupRead(t, f, sources[0], adjacent, "192.0.2.9", routingViewBudget()); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
		t.Fatal("adjacent route view impersonated a selected router lookup", got, err)
	}
}

func TestBGPRoutingLookupRefusesChangedAuthorityClockCorruptionAndMixedSnapshots(t *testing.T) {
	f := newRoleInputsFixture(t)
	source := routingFixtureSource(f, 0)
	ref := routingLookupBegin(t, f, source, routingLookupDefinition(1))
	first := routingChangeFixture()
	first.HasPathID = false
	first.PathID = 0
	second := routingChangeFixture()
	routingLookupApply(t, f, source, ref, BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, Changes: []BGPRoutingChange{first, second}})
	routingLookupApply(t, f, source, ref, BGPRoutingBatch{Sequence: 2, AFI: 1, SAFI: 1, EndOfRIB: true})
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID))
	if err := tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := (BGPRouting{}).lookupViewInScope(ctx, sc, source, ref, netip.MustParseAddr("192.0.2.9"), routingViewBudget())
		if !errors.Is(err, errBGPRoutingReadSnapshot) || got.Paths != nil {
			t.Fatal("routing lookup mixed nonrepeatable statements", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("rollback modeled source/read corruption")
	for _, tc := range []struct {
		name, sql string
		want      error
	}{
		{"sender-revoked", `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND agent_id='role-listener'`, ErrBGPRoutingSourceUnavailable},
		{"origin-purpose", `UPDATE agent_identities SET spiffe_id='spiffe://probectl/wrong-purpose' WHERE tenant_id=$1 AND agent_id='role-router'`, ErrBGPRoutingSourceUnavailable},
		{"source-rebound", `UPDATE entity_source_contexts SET assigned_at=transaction_timestamp() WHERE tenant_id=$1 AND source_kind='bmp_peer'`, ErrBGPRoutingSourceUnavailable},
		{"collector-reassigned", `UPDATE entity_agent_contexts SET assigned_at=transaction_timestamp() WHERE tenant_id=$1 AND agent_id='role-listener'`, ErrBGPRoutingSourceUnavailable},
		{"expired-view", `UPDATE bgp_routing_views SET valid_until=observed_at+interval '1 microsecond' WHERE tenant_id=$1`, ErrBGPRoutingSourceUnavailable},
		{"missing-clock", `UPDATE bgp_routing_views SET last_message_observed_at=NULL,message_clock_sequence=NULL WHERE tenant_id=$1`, ErrBGPRoutingSourceUnavailable},
		{"filtered-view", `UPDATE bgp_routing_views SET filtered=true WHERE tenant_id=$1`, ErrBGPRoutingSourceUnavailable},
		{"invalid-view", `UPDATE bgp_routing_views SET state='invalid' WHERE tenant_id=$1`, ErrBGPRoutingSourceUnavailable},
		{"corrupt-later-path", `UPDATE bgp_routing_entries SET segments='[{"Kind":7,"Values":[1]}]'::jsonb WHERE tenant_id=$1 AND has_path_id`, ErrBGPRoutingBatch},
		{"future-route-sequence", `UPDATE bgp_routing_entries SET sequence=99 WHERE tenant_id=$1 AND has_path_id`, ErrBGPRoutingView},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
				return tenancy.InTenantWriteSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
					if _, err := sc.Q.Exec(ctx, tc.sql, source.TenantID); err != nil {
						return err
					}
					recent := source
					if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&recent.ObservedAt); err != nil {
						return err
					}
					got, err := (BGPRouting{}).lookupViewInScope(ctx, sc, recent, ref, netip.MustParseAddr("192.0.2.9"), routingViewBudget())
					if !errors.Is(err, tc.want) || got.Paths != nil || got.Prefix.IsValid() {
						t.Fatal("changed routing authority or corrupt path retained attribution", got, err)
					}
					return rollback
				})
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
			got, err := routingLookupRead(t, f, source, ref, "192.0.2.9", routingViewBudget())
			if err != nil || len(got.Paths) != 2 {
				t.Fatal("refused lookup escaped rollback", err)
			}
		})
	}
	foreign := source
	foreign.RouterID = f.otherRouter
	if got, err := routingLookupRead(t, f, foreign, ref, "192.0.2.9", routingViewBudget()); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
		t.Fatal("lookup used a route from another router", got, err)
	}
	if got, err := routingLookupRead(t, f, source, ref, "203.0.113.9", routingViewBudget()); !errors.Is(err, errBGPRoutingRouteMissing) || got.Paths != nil {
		t.Fatal("missing complete route manufactured a path", got, err)
	}
}
