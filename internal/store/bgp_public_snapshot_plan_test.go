// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func publicSnapshotFixture() (BGPPublicSnapshotInput, BGPRoutingBudget) {
	first := publicRoutingMetadataFixture()
	second := publicRoutingMetadataFixture()
	second.AFI = 1
	third := publicRoutingMetadataFixture()
	third.Public.PeerAddress = netip.MustParseAddr("192.0.2.9")
	return BGPPublicSnapshotInput{CollectorAgentID: "role-listener", SenderSerial: "issued", SourceRef: publicRoutingSourceRef(*first.Public), ObservationID: "55555555-5555-4555-8555-555555555555", ObservedAt: time.Unix(1700000100, 987654321), Definitions: []BGPRoutingViewDefinition{first, second, third}}, BGPRoutingBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, StateBytes: 16 << 20, LeaseDuration: time.Hour}
}

func TestPublicSnapshotManifestKeepsBothFamiliesWholeIdentityExactClocksAndEmptyPresence(t *testing.T) {
	input, budget := publicSnapshotFixture()
	input.Definitions[0].Public.ViewName = []byte{0, 255, 7}
	peers, digest, remaining, err := preparePublicSnapshot(t.Context(), input, budget)
	if err != nil || len(peers) != len(input.Definitions) || digest == ([32]byte{}) || remaining.MemoryBytes >= budget.MemoryBytes || remaining.WorkUnits >= budget.WorkUnits {
		t.Fatal("whole public peer manifest lost identity, family or finite admission", err)
	}
	reversed := input
	reversed.Definitions = slices.Clone(input.Definitions)
	slices.Reverse(reversed.Definitions)
	_, same, _, err := preparePublicSnapshot(t.Context(), reversed, budget)
	if err != nil || same != digest {
		t.Fatal("public peer manifest identity depended on input ordering", err)
	}
	input.Definitions[0].Public.ViewName[0] = 99
	for _, retained := range peers {
		var peer BGPPublicRoutingPeer
		if err := json.Unmarshal(retained.Body, &peer); err != nil {
			t.Fatal(err)
		}
		if peer.CollectorObservedUnixNanos == nil || *peer.CollectorObservedUnixNanos != input.ObservedAt.UnixNano() || peer.ObservedUnixNanos == nil || *peer.ObservedUnixNanos != 1700000000123456789 || (len(peer.ViewName) == 3 && peer.ViewName[0] != 0) {
			t.Fatal("public manifest changed original/collector clocks or retained caller bytes")
		}
	}
	_, changed, _, err := preparePublicSnapshot(t.Context(), input, budget)
	if err != nil || changed == digest {
		t.Fatal("complete public source metadata disappeared from manifest identity", err)
	}
	input.Definitions = []BGPRoutingViewDefinition{}
	empty, emptyDigest, _, err := preparePublicSnapshot(t.Context(), input, budget)
	if err != nil || empty == nil || len(empty) != 0 || emptyDigest == ([32]byte{}) {
		t.Fatal("complete empty peer manifest became unavailable", err)
	}
	zero := int64(0)
	input.SourceObservedUnixNanos = &zero
	if _, known, _, err := preparePublicSnapshot(t.Context(), input, budget); err != nil || known == emptyDigest {
		t.Fatal("empty public manifest lost original source clock presence", err)
	}
	input.SourceObservedUnixNanos = nil
	input.Definitions = nil
	if peers, key, _, err := preparePublicSnapshot(t.Context(), input, budget); err == nil || peers != nil || key != ([32]byte{}) {
		t.Fatal("missing public manifest became a complete empty withdrawal", err)
	}
}

func TestPublicSnapshotManifestIdentityDoesNotRequireAReplacementLease(t *testing.T) {
	input, budget := publicSnapshotFixture()
	_, original, _, err := preparePublicSnapshot(t.Context(), input, budget)
	if err != nil {
		t.Fatal(err)
	}
	budget.LeaseDuration = 0
	peers, retained, _, err := preparePublicSnapshot(t.Context(), input, budget)
	if err != nil || retained != original || len(peers) != len(input.Definitions) {
		t.Fatal("immutable public manifest required a new lease or changed original source identity", err)
	}
}

func TestPublicSnapshotManifestRefusesLatePartialBudgetAndForeignTenantBeforeStorage(t *testing.T) {
	for _, mutate := range []func(*BGPPublicSnapshotInput){
		func(i *BGPPublicSnapshotInput) { i.Definitions = append(i.Definitions, i.Definitions[0]) },
		func(i *BGPPublicSnapshotInput) { i.Definitions[len(i.Definitions)-1].Public = nil },
		func(i *BGPPublicSnapshotInput) { i.Definitions[len(i.Definitions)-1].Filtered = true },
		func(i *BGPPublicSnapshotInput) { i.Definitions[len(i.Definitions)-1].Kind = "loc_rib" },
		func(i *BGPPublicSnapshotInput) { i.Definitions[len(i.Definitions)-1].Public.Collector = "unassigned" },
		func(i *BGPPublicSnapshotInput) { i.ObservationID = "not-an-observation" },
	} {
		input, budget := publicSnapshotFixture()
		mutate(&input)
		if peers, key, _, err := preparePublicSnapshot(t.Context(), input, budget); err == nil || peers != nil || key != ([32]byte{}) {
			t.Fatal("incomplete public manifest returned a partial staging plan", err)
		}
	}
	input, budget := publicSnapshotFixture()
	budget.MemoryBytes = 4096
	if peers, key, _, err := preparePublicSnapshot(t.Context(), input, budget); !errors.Is(err, ErrBGPRoutingBudget) || peers != nil || key != ([32]byte{}) {
		t.Fatal("public manifest escaped whole operation admission", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if peers, _, _, err := preparePublicSnapshot(ctx, input, budget); !errors.Is(err, context.Canceled) || peers != nil {
		t.Fatal("public manifest ignored cancellation", err)
	}
	const tenant = "11111111-1111-4111-8111-111111111111"
	const foreign = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	for _, pair := range []struct {
		ctx context.Context
		sc  tenancy.Scope
	}{
		{t.Context(), tenancy.Scope{Tenant: tenancy.ID(tenant)}},
		{tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), tenancy.Scope{Tenant: tenancy.ID(foreign)}},
	} {
		if out, err := (BGPRouting{}).StagePublicSnapshotInScope(pair.ctx, pair.sc, input, budget); !errors.Is(err, entity.ErrScopeMismatch) || out.ID != "" || out.Views != nil {
			t.Fatal("public staging admitted foreign tenant before storage", out, err)
		}
	}
}
