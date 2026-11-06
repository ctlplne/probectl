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
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual tenant application-role Postgres; the service decoder and source
// identity rows are modeled here. The separate wire root proves real mTLS.
func TestBGPRoutingWholeStreamKeepsFamilyAtomicityReplayAndTenantFence(t *testing.T) {
	f := newRoleInputsFixture(t)
	profile := routingViewBudget()
	profile.LeaseDuration = 5 * time.Minute
	sources := []BGPRoutingSource{routingFixtureSource(f, 0), routingFixtureSource(f, 1)}
	inputs := make([]BGPRoutingStreamInput, 2)
	for lane, source := range sources {
		nonce := uuid.NewString()
		up := BGPRoutingPeerUpInput{CollectorAgentID: source.CollectorAgentID, SenderSerial: source.SenderSerial, SourceRef: source.SourceRef,
			OriginSerial: source.OriginSerial, ObservationID: nonce, ObservedAt: source.ObservedAt, FrameDigest: crypto.Hash([]byte("complete peer up")),
			Definitions: []BGPRoutingViewDefinition{routingLookupDefinition(1), routingLookupDefinition(2)}}
		if err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
			result, err := (BGPRouting{}).StagePeerInScope(ctx, sc, up, profile)
			if err == nil && result.Status != "staged" {
				t.Fatal("stream prerequisite staging failed", result)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		inputs[lane] = BGPRoutingStreamInput{CollectorAgentID: source.CollectorAgentID, SenderSerial: source.SenderSerial, SourceRef: source.SourceRef,
			OriginSerial: source.OriginSerial, Generation: nonce}
	}
	count := func(lane int, table, predicate string) int {
		var total int
		f.in(sources[lane].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1 "+predicate, sources[lane].TenantID).Scan(&total)
		})
		return total
	}
	batches := func(mode string) []BGPRoutingBatch {
		out := []BGPRoutingBatch{{AFI: 1, SAFI: 1, Heartbeat: true, WireDigest: crypto.Hash([]byte(mode))}, {AFI: 2, SAFI: 1, Heartbeat: true, WireDigest: crypto.Hash([]byte(mode))}}
		switch mode {
		case "routes", "late-fault":
			for i := range out {
				change := routingChangeFixture()
				if i == 1 {
					change.Prefix = netip.MustParsePrefix("2001:db8:1::/48")
					change.NextHops = []netip.Addr{netip.MustParseAddr("2001:db8::1")}
				}
				if mode == "late-fault" {
					change.Segments[0].Values[0] = 4200000001
				}
				out[i].Heartbeat, out[i].Changes = false, []BGPRoutingChange{change}
			}
		case "v4-eor":
			out[0].Heartbeat, out[0].EndOfRIB = false, true
		case "v6-eor":
			out[1].Heartbeat, out[1].EndOfRIB = false, true
		}
		return out
	}
	apply := func(lane int, input BGPRoutingStreamInput, mode string, fault bool) BGPRoutingApplyResult {
		var result BGPRoutingApplyResult
		err := routingFixtureWrite(t, f, sources[lane], func(ctx context.Context, sc tenancy.Scope) error {
			if fault {
				sc.Q = &routingFaultWriter{Querier: sc.Q, fault: func(context.Context) error { return errors.New("modeled late second-family write fault") }}
			}
			var err error
			result, err = (BGPRouting{}).ApplyPeerMessageInScope(ctx, sc, input, profile,
				func(context.Context, BGPRoutingPeer, []BGPRoutingStagedView) ([]BGPRoutingBatch, error) {
					if mode == "decode-refusal" {
						return nil, ErrBGPRoutingBatch
					}
					return batches(mode), nil
				})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	for lane := range sources {
		for i, mode := range []string{"routes", "v4-eor", "v6-eor"} {
			inputs[lane].Sequence, inputs[lane].ObservedAt = int64(i+1), routingFixtureTime(f)
			if got := apply(lane, inputs[lane], mode, false); got.Status != "applied" {
				t.Fatal("complete source family progress refused", mode, got)
			}
			if i == 1 && count(lane, "bgp_routing_views", "AND state='current'") != 1 {
				t.Fatal("one EOR published another address family")
			}
		}
		if count(lane, "bgp_routing_entries", "") != 2 || count(lane, "bgp_routing_views", "AND state='current'") != 2 {
			t.Fatal("complete source family publication lost retained paths")
		}
		if got := apply(lane, inputs[lane], "v6-eor", false); got.Status != "replayed" {
			t.Fatal("exact complete message retry changed source state", got)
		}
	}
	inputs[0].Sequence, inputs[0].ObservedAt = 4, routingFixtureTime(f)
	if got := apply(0, inputs[0], "late-fault", true); got.Status != "invalidated" || count(0, "bgp_routing_views", "AND state='current'") != 0 || count(1, "bgp_routing_views", "AND state='current'") != 2 {
		t.Fatal("late family fault escaped whole-message rollback or tenant isolation", got)
	}
	// The first family's changed path must also have rolled back, even though
	// its UPDATE completed before the second family failed.
	if count(0, "bgp_routing_entries", "AND segments::text LIKE '%4200000001%'") != 0 {
		t.Fatal("late family fault left a partial retained path")
	}
	inputs[1].Sequence, inputs[1].ObservedAt = 5, routingFixtureTime(f) // omit frame four
	if got := apply(1, inputs[1], "heartbeat", false); got.Status != "invalidated" || count(1, "bgp_routing_views", "AND state='current'") != 0 {
		t.Fatal("whole-source sequence gap retained current routing state", got)
	}
	foreign := inputs[0]
	foreign.Generation = inputs[1].Generation
	if got := apply(0, foreign, "routes", false); got.Status != "invalidated" {
		t.Fatal("foreign generation became routing authority", got)
	}
}
