// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cluster

import (
	"context"
	"testing"
)

// TestWriterUsableNowFencesLostPrimaryBeforeProbe (RTO-19): the write fence
// must be authoritative at write TIME, not only after the next ~5s probe. A
// node that stops being the primary between probes — demoted to a read-only
// standby on failover — must fence the VERY NEXT write, so ZERO writes are
// acknowledged after the switch. The cached verdict (WriterUsable) is still
// stale-usable in that window: that is precisely the acknowledge-and-lose bug
// WriterUsableNow closes.
func TestWriterUsableNowFencesLostPrimaryBeforeProbe(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{InRecovery: false, Epoch: 1, WriterRegion: "us-east"}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 1, WriterRegion: "us-east", LagSeconds: 0.1}}
	m := NewManager(topo(), writer, reader)

	// Steady state: the periodic probe has run; this node is the primary and a
	// write is acknowledged (the fence says usable).
	m.Refresh(ctx)
	if ok, reason := m.WriterUsableNow(ctx); !ok {
		t.Fatalf("a healthy primary must acknowledge writes at write time: %s", reason)
	}

	// Failover WITHOUT a probe tick: the writer endpoint now resolves to a
	// read-only ex-primary (this node was demoted). The periodic Refresh has NOT
	// run, so the cached verdict is still stale-usable — the pre-probe window.
	writer.set(Probe{InRecovery: true, Epoch: 1, WriterRegion: "us-east"})
	if ok, _ := m.WriterUsable(); !ok {
		t.Fatal("precondition: the cached verdict is still usable in the pre-probe window (the RTO-19 window this test pins)")
	}

	// The authoritative write-path check re-probes synchronously and fences the
	// very next write: zero writes acknowledged after the switch.
	if ok, reason := m.WriterUsableNow(ctx); ok {
		t.Fatalf("RTO-19: a node that stopped being the primary must fence the next write synchronously, got usable (reason=%q)", reason)
	}
}

// TestWriterUsableNowFencesStaleEpochBeforeProbe (RTO-19, split-brain variant):
// a promotion elsewhere advances the epoch on the replica that follows the TRUE
// primary while the writer endpoint still resolves to the ex-primary on the OLD
// epoch. The authoritative check re-probes the replica, raises the high-water
// mark, and fences the stale ex-primary on the next write — before the periodic
// Refresh would have folded the new epoch in.
func TestWriterUsableNowFencesStaleEpochBeforeProbe(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{InRecovery: false, Epoch: 1, WriterRegion: "us-east"}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 1, WriterRegion: "us-east"}}
	m := NewManager(topo(), writer, reader)

	m.Refresh(ctx)
	if ok, reason := m.WriterUsableNow(ctx); !ok {
		t.Fatalf("a healthy primary must be usable: %s", reason)
	}

	// A promotion elsewhere bumps the epoch to 2; the replica already follows it
	// while the writer endpoint still points at the ex-primary on epoch 1. No
	// periodic Refresh has run, so the cached verdict is still usable.
	reader.set(Probe{InRecovery: true, Epoch: 2, WriterRegion: "eu-west"})
	if ok, _ := m.WriterUsable(); !ok {
		t.Fatal("precondition: the cached verdict is still usable before the probe folds in the new epoch")
	}

	if ok, reason := m.WriterUsableNow(ctx); ok {
		t.Fatalf("RTO-19: a stale ex-primary (epoch 1 < 2) must fence the next write synchronously, got usable (reason=%q)", reason)
	}
}

// TestWriterUsableNowFailsClosedBeforeFirstProbe: the authoritative check still
// fails closed before the first periodic probe has established a baseline —
// startup is the riskiest moment for split-brain.
func TestWriterUsableNowFailsClosedBeforeFirstProbe(t *testing.T) {
	m := NewManager(topo(), &fakeProbe{p: Probe{Epoch: 1}}, nil)
	if ok, reason := m.WriterUsableNow(context.Background()); ok || reason == "" {
		t.Fatalf("writes must be fenced until the first probe resolves: ok=%v reason=%q", ok, reason)
	}
}

// TestWriterUsableNowHappyPathStaysUsable: the true current primary keeps
// acknowledging writes through the authoritative check (no false fence).
func TestWriterUsableNowHappyPathStaysUsable(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{InRecovery: false, Epoch: 2, WriterRegion: "eu-west"}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 2, WriterRegion: "eu-west", LagSeconds: 0.2}}
	m := NewManager(topo(), writer, reader)
	m.Refresh(ctx)
	for i := 0; i < 3; i++ {
		if ok, reason := m.WriterUsableNow(ctx); !ok {
			t.Fatalf("the current primary must stay usable on repeated write-path checks: %s", reason)
		}
	}
}
