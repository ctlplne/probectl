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
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real application-role Postgres; source identities and protocol metadata are
// modeled. Public ingress still keeps its separate non-global context fence.
func TestRoutingBoundStagingKeepsSelectorIncarnationsAndSourceWideRefusal(t *testing.T) {
	f := newRoleInputsFixture(t)
	profile := routingViewBudget()
	profile.LeaseDuration = 5 * time.Minute
	targetContext, targetRouter := uuid.NewString(), uuid.NewString()
	bindings := []routingSourceBinding{
		{ContextID: targetContext, RouterID: targetRouter, Distinguisher: "0000000000000001", BGPIdentifier: "192.0.2.1", Families: []uint16{1, 2}},
		{ContextID: targetContext, RouterID: targetRouter, Distinguisher: "0000000000000001", BGPIdentifier: "192.0.2.2", Families: []uint16{1, 2}},
	}
	manifests := make([]routingSourceManifest, len(f.tenants))
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$2,$2,'owned','routed')`, tenant, targetContext); err != nil {
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
	up := func(lane, selector int, nonce string) BGPRoutingPeerUpInput {
		source := routingFixtureSource(f, lane)
		input := BGPRoutingPeerUpInput{CollectorAgentID: source.CollectorAgentID, SenderSerial: source.SenderSerial, SourceRef: source.SourceRef,
			OriginSerial: source.OriginSerial, ObservationID: nonce, ObservedAt: source.ObservedAt,
			FrameDigest: crypto.Hash([]byte(fmt.Sprintf("whole-peer-up-%d-%d-%s", lane, selector, nonce)))}
		for _, afi := range []uint16{1, 2} {
			definition := routingLookupDefinition(afi)
			definition.Peer.Distinguisher[7] = 1
			definition.Peer.BGPIdentifier = netip.MustParseAddr(bindings[selector].BGPIdentifier)
			input.Definitions = append(input.Definitions, definition)
		}
		return input
	}
	stage := func(lane int, input BGPRoutingPeerUpInput) (BGPRoutingStageResult, error) {
		var result BGPRoutingStageResult
		err := routingFixtureWrite(t, f, routingFixtureSource(f, lane), func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			result, err = (BGPRouting{}).StagePeerInScope(ctx, sc, input, profile)
			return err
		})
		return result, err
	}
	count := func(lane int) int {
		var total int
		f.in(f.tenants[lane], func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE state IN ('staging','current')`).Scan(&total)
		})
		return total
	}
	nonces := []string{uuid.NewString(), uuid.NewString()}
	for lane := range f.tenants {
		for selector := range bindings {
			input := up(lane, selector, nonces[selector])
			result, err := stage(lane, input)
			if err != nil || result.Status != "staged" || len(result.Views) != 2 {
				t.Fatal("owned explicitly bound source was refused", result, err)
			}
			retry, err := stage(lane, input)
			if err != nil || retry.Status != "replayed" || len(retry.Views) != 2 || retry.Views[0] != result.Views[0] || retry.Views[1] != result.Views[1] {
				t.Fatal("bound exact retry changed its private incarnation", retry, err)
			}
		}
		if count(lane) != 4 {
			t.Fatal("routing source selector retired a sibling binding or tenant", lane, count(lane))
		}
	}
	ambiguous := up(0, 0, uuid.NewString())
	ambiguous.Definitions[1].Peer.ASN = 64496
	if result, err := stage(0, ambiguous); err != nil || result.Status != "invalidated" || len(result.Views) != 0 || count(0) != 2 || count(1) != 4 {
		t.Fatal("mixed complete routing peers were staged as one generation", result, err)
	}
	if result, err := stage(0, up(0, 0, uuid.NewString())); err != nil || result.Status != "staged" || count(0) != 4 {
		t.Fatal("fresh bound source could not recover after metadata refusal", result, err)
	}
	unbound := up(0, 0, uuid.NewString())
	for i := range unbound.Definitions {
		unbound.Definitions[i].Peer.BGPIdentifier = netip.MustParseAddr("192.0.2.99")
	}
	if _, err := stage(0, unbound); !errors.Is(err, errBGPRoutingContextBinding) || count(0) != 4 || count(1) != 4 {
		t.Fatal("unbound selector changed an owned routing source", err)
	}
	refused := up(0, 0, uuid.NewString())
	hint := refused.Definitions[0].Peer
	refused.RefusedPeer, refused.Definitions = &hint, nil
	if got, err := stage(0, refused); err != nil || got.Status != "invalidated" || len(got.Views) != 0 || count(0) != 2 || count(1) != 4 {
		t.Fatal("selector refusal retired sibling bindings or created routing authority", got, err, count(0), count(1))
	}
	if got, err := stage(0, up(0, 0, uuid.NewString())); err != nil || got.Status != "staged" || count(0) != 4 {
		t.Fatal("selected source could not restart after scoped refusal", got, err)
	}
	replacement := up(0, 0, uuid.NewString())
	replacement.Definitions = replacement.Definitions[:1]
	if got, err := stage(0, replacement); err != nil || got.Status != "staged" || count(0) != 3 || count(1) != 4 {
		t.Fatal("bound replacement retained omitted family or changed another selector", got, err, count(0), count(1))
	}
	bad := up(0, 0, uuid.NewString())
	bad.Definitions = nil
	foreign := bad
	foreign.OriginSerial = f.serials[f.tenants[1]+"role-router"]
	if _, err := stage(0, foreign); err == nil || count(0) != 3 || count(1) != 4 {
		t.Fatal("foreign credential authorized routing source-wide invalidation", err)
	}
	if result, err := stage(0, bad); err != nil || result.Status != "invalidated" || len(result.Views) != 0 || count(0) != 0 || count(1) != 4 {
		t.Fatal("unusable bound source retained prior views or changed another tenant", result, err)
	}
	source := routingFixtureSource(f, 0)
	if err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		manifests[0], err = putRoutingBindings(ctx, sc, source.CollectorAgentID, source.SourceRef, source.ContextID, manifests[0].Epoch, bindings, profile)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if result, err := stage(0, up(0, 0, nonces[0])); err != nil || result.Status != "invalidated" || len(result.Views) != 0 || count(0) != 0 {
		t.Fatal("former routing observation UUID borrowed a replacement binding", result, err)
	}
	barrier := up(0, 0, uuid.NewString())
	barrier.Definitions = nil
	if result, err := stage(0, up(0, 0, uuid.NewString())); err != nil || result.Status != "staged" || count(0) != 2 {
		t.Fatal("fresh observation could not use replacement operator binding", result, err)
	}
	if result, err := stage(0, barrier); err != nil || result.Status != "invalidated" || count(0) != 2 || count(1) != 4 {
		t.Fatal("queued old invalidation retired a newer routing source", result, err)
	}
}
