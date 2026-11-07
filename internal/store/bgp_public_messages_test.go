// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func publicMessageFixture() (BGPPublicSnapshotMessage, BGPRoutingBudget) {
	input, profile := publicSnapshotFixture()
	batch := BGPPublicSnapshotBatch{BGPRoutingViewRef: BGPRoutingViewRef{ID: "66666666-6666-4666-8666-666666666666", Generation: "77777777-7777-4777-8777-777777777777"}, BGPRoutingBatch: BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: input.ObservedAt, Changes: []BGPRoutingChange{routingChangeFixture()}}}
	return BGPPublicSnapshotMessage{CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: input.SourceRef, SnapshotID: input.ObservationID, Sequence: 1, ObservedAt: input.ObservedAt, WireDigest: make([]byte, 32), Batches: []BGPPublicSnapshotBatch{batch}}, profile
}

func TestPublicSnapshotMessageKeepsWholePathsExactReplayAndExclusiveCompletion(t *testing.T) {
	input, profile := publicMessageFixture()
	path := make([]uint32, 65538)
	for i := range path {
		path[i] = math.MaxUint32 - uint32(i%3)
	}
	input.Batches[0].Changes[0].Segments[1].Values = path
	prepared, digest, err := preparePublicSnapshotMessage(t.Context(), input, profile)
	if err != nil || len(prepared) != 1 || len(prepared[0].changes) != 1 || len(prepared[0].changes[0].Segments[1].Values) != len(path) || prepared[0].changes[0].PathID != math.MaxUint32 || prepared[0].digest == ([32]byte{}) {
		t.Fatal("public message lost complete path or source replay identity", err)
	}
	_, same, err := preparePublicSnapshotMessage(t.Context(), input, profile)
	if err != nil || same != digest {
		t.Fatal("unchanged public message changed replay identity", err)
	}
	input.WireDigest[0] = 1
	if _, changed, err := preparePublicSnapshotMessage(t.Context(), input, profile); err != nil || changed == digest {
		t.Fatal("public source frame digest disappeared from message identity", err)
	}
	input.Batches = nil
	input.Complete = true
	if batches, _, err := preparePublicSnapshotMessage(t.Context(), input, profile); err != nil || len(batches) != 0 {
		t.Fatal("exclusive source completion required a fabricated peer batch", err)
	}
}

func TestPublicSnapshotMessageRefusesLatePartialShapeBudgetAndForeignScope(t *testing.T) {
	for _, mutate := range []func(*BGPPublicSnapshotMessage){
		func(i *BGPPublicSnapshotMessage) { i.Batches = append(i.Batches, i.Batches[0]) },
		func(i *BGPPublicSnapshotMessage) { i.Batches[0].Generation = "invalid" },
		func(i *BGPPublicSnapshotMessage) { i.Batches[0].Sequence++ },
		func(i *BGPPublicSnapshotMessage) { i.Batches[0].ObservedAt = i.ObservedAt.Add(time.Nanosecond) },
		func(i *BGPPublicSnapshotMessage) { i.Batches[0].Heartbeat = true },
		func(i *BGPPublicSnapshotMessage) { i.Batches[0].EndOfRIB = true; i.Batches[0].Changes = nil },
		func(i *BGPPublicSnapshotMessage) { i.Complete = true },
		func(i *BGPPublicSnapshotMessage) { i.Reset = true },
		func(i *BGPPublicSnapshotMessage) { i.WireDigest = nil },
		func(i *BGPPublicSnapshotMessage) { i.Sequence = math.MaxInt64 },
	} {
		input, profile := publicMessageFixture()
		mutate(&input)
		if out, digest, err := preparePublicSnapshotMessage(t.Context(), input, profile); err == nil || out != nil || digest != ([32]byte{}) {
			t.Fatal("malformed public message exposed a partial batch", err)
		}
	}
	input, profile := publicMessageFixture()
	profile.MemoryBytes = 4096
	if out, digest, err := preparePublicSnapshotMessage(t.Context(), input, profile); !errors.Is(err, ErrBGPRoutingBudget) || out != nil || digest != ([32]byte{}) {
		t.Fatal("public message escaped whole admission", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if out, _, err := preparePublicSnapshotMessage(ctx, input, profile); !errors.Is(err, context.Canceled) || out != nil {
		t.Fatal("canceled public message retained work", err)
	}
	const tenant = "11111111-1111-4111-8111-111111111111"
	if out, err := (BGPRouting{}).ApplyPublicSnapshotMessageInScope(t.Context(), tenancy.Scope{Tenant: tenancy.ID(tenant)}, input, profile, time.Hour); !errors.Is(err, entity.ErrScopeMismatch) || out.Status != "" {
		t.Fatal("public message used storage before tenant scope", out, err)
	}
}
