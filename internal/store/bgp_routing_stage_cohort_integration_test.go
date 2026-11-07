// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual application-role Postgres/RLS; complete peer metadata is modeled.
// The same source key, family and generation nonce exist in both tenants.
func TestRoutingStageKeepsDisjointCohortsAndRetiresWholeOverlap(t *testing.T) {
	f := newRoleInputsFixture(t)
	profile := routingViewBudget()
	profile.LeaseDuration = 5 * time.Minute
	sources := []BGPRoutingSource{routingFixtureSource(f, 0), routingFixtureSource(f, 1)}
	var changedIdentifier string
	stage := func(lane int, nonce string, families ...uint16) {
		t.Helper()
		source := sources[lane]
		up := BGPRoutingPeerUpInput{CollectorAgentID: source.CollectorAgentID, SenderSerial: source.SenderSerial, SourceRef: source.SourceRef, OriginSerial: source.OriginSerial, ObservationID: nonce, ObservedAt: routingFixtureTime(f), FrameDigest: crypto.Hash([]byte(fmt.Sprint("complete modeled cohort", nonce, families)))}
		for _, afi := range families {
			definition := routingLookupDefinition(afi)
			if changedIdentifier != "" {
				definition.Peer.BGPIdentifier = netip.MustParseAddr(changedIdentifier)
			}
			up.Definitions = append(up.Definitions, definition)
		}
		var got BGPRoutingStageResult
		err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			got, err = (BGPRouting{}).StagePeerInScope(ctx, sc, up, profile)
			return err
		})
		if err != nil || got.Status != "staged" || len(got.Views) != len(families) {
			t.Fatal("complete source cohort did not stage", families, got, err)
		}
	}
	active := func(lane int, nonce string) int {
		t.Helper()
		var count int
		f.in(f.tenants[lane], func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE tenant_id=$1 AND ($2::text='' OR generation=$2::uuid) AND state IN ('staging','current')`, f.tenants[lane], nonce).Scan(&count)
		})
		return count
	}
	first, second := uuid.NewString(), uuid.NewString()
	for lane := range sources {
		stage(lane, first, 1)
	}
	stage(0, second, 2)
	if active(0, first) != 1 || active(0, second) != 1 || active(1, first) != 1 {
		t.Fatal("disjoint IPv6 Peer Up retired IPv4 or another tenant")
	}
	stage(1, second, 2)
	replacement := uuid.NewString()
	stage(0, replacement, 1)
	if active(0, first) != 0 || active(0, second) != 1 || active(0, replacement) != 1 || active(1, first) != 1 || active(1, second) != 1 {
		t.Fatal("single-family replacement retained overlap or retired a disjoint cohort or tenant")
	}
	combined := uuid.NewString()
	stage(0, combined, 1, 2)
	if active(0, replacement) != 0 || active(0, second) != 0 || active(0, combined) != 2 {
		t.Fatal("combined Peer Up did not retire every overlapping cohort")
	}
	shrunk := uuid.NewString()
	stage(0, shrunk, 1)
	if active(0, combined) != 0 || active(0, shrunk) != 1 || active(1, first) != 1 || active(1, second) != 1 {
		t.Fatal("replacement retained omitted family from combined cohort or changed a sibling tenant")
	}
	v6 := uuid.NewString()
	stage(0, v6, 2)
	changedIdentifier = "192.0.2.99"
	newIdentity := uuid.NewString()
	stage(0, newIdentity, 1)
	if active(0, shrunk) != 0 || active(0, v6) != 0 || active(0, newIdentity) != 1 || active(1, first) != 1 || active(1, second) != 1 {
		t.Fatal("changed protocol identity retained a disjoint old cohort or changed a sibling tenant")
	}

}
