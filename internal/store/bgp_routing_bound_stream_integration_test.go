// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual TLS Postgres/FORCE-RLS and source writers; callback projection and
// source identities are modeled. This is not physical router or mTLS proof.
func TestRoutingBoundStreamKeepsWholeCurrentGenerationsAndRefusalIsolation(t *testing.T) {
	f := newRoleInputsFixture(t)
	profile := routingViewBudget()
	profile.LeaseDuration = 5 * time.Minute
	targetContext, targetRouter := uuid.NewString(), uuid.NewString()
	bindings := []routingSourceBinding{
		{ContextID: targetContext, RouterID: targetRouter, Distinguisher: "0000000000000001", BGPIdentifier: "192.0.2.9", Families: []uint16{1, 2}},
		{ContextID: targetContext, RouterID: targetRouter, Distinguisher: "0000000000000002", BGPIdentifier: "192.0.2.9", Families: []uint16{1, 2}},
	}
	manifests := make([]routingSourceManifest, 2)
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'owned','routing')`, tenant, targetContext); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','target')`, tenant, targetContext, targetRouter)
			return err
		})
		source := routingFixtureSource(f, lane)
		if err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			manifests[lane], err = putRoutingBindings(ctx, sc, source.CollectorAgentID, source.SourceRef, source.ContextID, "", bindings, profile)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	stage := func(lane, selector int, nonce string) BGPRoutingStreamInput {
		source := routingFixtureSource(f, lane)
		up := BGPRoutingPeerUpInput{CollectorAgentID: source.CollectorAgentID, SenderSerial: source.SenderSerial, SourceRef: source.SourceRef,
			OriginSerial: source.OriginSerial, ObservationID: nonce, ObservedAt: source.ObservedAt, FrameDigest: crypto.Hash([]byte("complete bound peer up"))}
		for _, afi := range []uint16{1, 2} {
			definition := routingLookupDefinition(afi)
			definition.Peer.Distinguisher[7] = byte(selector + 1)
			up.Definitions = append(up.Definitions, definition)
		}
		if err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
			got, err := (BGPRouting{}).StagePeerInScope(ctx, sc, up, profile)
			if err == nil && (got.Status != "staged" || len(got.Views) != 2) {
				t.Fatal("bound stream staging prerequisite failed", got)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return BGPRoutingStreamInput{CollectorAgentID: source.CollectorAgentID, SenderSerial: source.SenderSerial, SourceRef: source.SourceRef, OriginSerial: source.OriginSerial, Generation: nonce}
	}
	apply := func(lane, selector int, input BGPRoutingStreamInput, mode string, budget BGPRoutingBudget) (BGPRoutingApplyResult, bool, error) {
		var result BGPRoutingApplyResult
		called := false
		err := routingFixtureWrite(t, f, routingFixtureSource(f, lane), func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			result, err = (BGPRouting{}).ApplyPeerMessageInScope(ctx, sc, input, budget,
				func(_ context.Context, peer BGPRoutingPeer, refs []BGPRoutingStagedView) ([]BGPRoutingBatch, error) {
					called = true
					if peer.Distinguisher[7] != byte(selector+1) {
						t.Fatal("wrong routing peer reached source decoder")
					}
					out := make([]BGPRoutingBatch, len(refs))
					for i, ref := range refs {
						out[i] = BGPRoutingBatch{AFI: ref.AFI, SAFI: ref.SAFI, Heartbeat: true, WireDigest: crypto.Hash([]byte(mode))}
						if mode == "routes" {
							change := routingChangeFixture()
							change.Segments[1].Values[0] = uint32(64496 + lane*10 + selector)
							if ref.AFI == 2 {
								change.Prefix = netip.MustParsePrefix("2001:db8:42::/48")
							}
							out[i].Heartbeat, out[i].Changes = false, []BGPRoutingChange{change}
						} else if mode == "v4-eor" && ref.AFI == 1 || mode == "v6-eor" && ref.AFI == 2 {
							out[i].Heartbeat, out[i].EndOfRIB = false, true
						}
					}
					return out, nil
				})
			return err
		})
		return result, called, err
	}
	count := func(lane int, generation string) int {
		var n int
		f.in(f.tenants[lane], func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE generation=$1 AND state IN ('staging','current')`, generation).Scan(&n)
		})
		return n
	}
	nonces := []string{uuid.NewString(), uuid.NewString()}
	inputs := make([][]BGPRoutingStreamInput, 2)
	for lane := range f.tenants {
		for selector := range bindings {
			input := stage(lane, selector, nonces[selector])
			for sequence, mode := range []string{"routes", "v4-eor", "v6-eor"} {
				input.Sequence, input.ObservedAt = int64(sequence+1), routingFixtureTime(f)
				if got, called, err := apply(lane, selector, input, mode, profile); err != nil || !called || got.Status != "applied" {
					t.Fatal("bound source message refused current complete generation", got, called, err)
				}
			}
			if got, _, err := apply(lane, selector, input, "v6-eor", profile); err != nil || got.Status != "replayed" || count(lane, input.Generation) != 2 {
				t.Fatal("bound exact stream retry changed complete source", got, err)
			}
			inputs[lane] = append(inputs[lane], input)
			f.in(f.tenants[lane], func(ctx context.Context, sc tenancy.Scope) error {
				var published int
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE generation=$1 AND state='current'`).Scan(&published); err != nil {
					return err
				}
				if published != 2 {
					t.Fatal("bound complete source did not publish both address families", published)
				}
				rows, err := sc.Q.Query(ctx, `SELECT segments FROM bgp_routing_entries WHERE generation=$1 ORDER BY afi`, input.Generation)
				if err != nil {
					return err
				}
				defer rows.Close()
				seen := 0
				for rows.Next() {
					var raw []byte
					if err := rows.Scan(&raw); err != nil {
						return err
					}
					var segments []BGPRoutingSegment
					if json.Unmarshal(raw, &segments) != nil || len(segments) != 3 || len(segments[1].Values) == 0 || segments[1].Values[0] != uint32(64496+lane*10+selector) {
						t.Fatal("bound source path borrowed another tenant or selector")
					}
					seen++
				}
				if seen != 2 {
					t.Fatal("bound source lost complete dual-family paths", seen)
				}
				return rows.Err()
			})
		}
	}
	message := inputs[0][0]
	message.Sequence, message.ObservedAt = 4, routingFixtureTime(f)
	small := profile
	small.MemoryBytes = 8192
	if got, called, err := apply(0, 0, message, "heartbeat", small); err != nil || called || got.Status != "invalidated" || count(0, nonces[0]) != 0 || count(0, nonces[1]) != 2 || count(1, nonces[0]) != 2 {
		t.Fatal("known routing admission refusal retained or crossed a source generation", got, called, err)
	}
	foreign := inputs[0][1]
	foreign.Sequence, foreign.ObservedAt, foreign.OriginSerial = 4, routingFixtureTime(f), inputs[1][1].OriginSerial
	if _, called, err := apply(0, 1, foreign, "heartbeat", profile); err == nil || called || count(0, nonces[1]) != 2 || count(1, nonces[1]) != 2 {
		t.Fatal("foreign origin reached bound stream or changed current routes", err)
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM bgp_routing_views WHERE generation=$1 AND afi=2`, nonces[1])
		return err
	})
	message = inputs[0][1]
	message.Sequence, message.ObservedAt = 4, routingFixtureTime(f)
	if got, called, err := apply(0, 1, message, "heartbeat", profile); err != nil || called || got.Status != "invalidated" || count(0, nonces[1]) != 0 || count(1, nonces[1]) != 2 {
		t.Fatal("incomplete retained source refreshed a surviving routing view", got, called, err)
	}
	message = inputs[1][0]
	message.Sequence, message.ObservedAt, message.Reset = 4, routingFixtureTime(f), true
	if got, called, err := apply(1, 0, message, "heartbeat", profile); err != nil || called || got.Status != "invalidated" || count(1, nonces[0]) != 0 || count(1, nonces[1]) != 2 {
		t.Fatal("bound reset crossed an independent source", got, called, err)
	}
	base := routingFixtureSource(f, 1)
	if err := routingFixtureWrite(t, f, base, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := putRoutingBindings(ctx, sc, base.CollectorAgentID, base.SourceRef, base.ContextID, manifests[1].Epoch, bindings, profile)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	fresh := stage(1, 1, uuid.NewString())
	for sequence, mode := range []string{"routes", "v4-eor", "v6-eor"} {
		fresh.Sequence, fresh.ObservedAt = int64(sequence+1), routingFixtureTime(f)
		if got, _, err := apply(1, 1, fresh, mode, profile); err != nil || got.Status != "applied" {
			t.Fatal("fresh current bound source could not recover", got, err)
		}
	}
	message = inputs[1][1]
	message.Sequence, message.ObservedAt = 4, routingFixtureTime(f)
	if got, called, err := apply(1, 1, message, "heartbeat", profile); err != nil || called || got.Status != "invalidated" || count(1, fresh.Generation) != 2 {
		t.Fatal("old bound generation invalidated or revived a replacement source", got, called, err)
	}
}
