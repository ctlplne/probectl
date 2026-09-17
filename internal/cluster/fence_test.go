// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cluster

import (
	"context"
	"testing"
)

// fakeFencer records what the manager asks of the writer pool.
type fakeFencer struct {
	on    bool
	calls []bool
}

func (f *fakeFencer) FenceWrites(on bool) bool {
	f.calls = append(f.calls, on)
	changed := f.on != on
	f.on = on
	return changed
}

// TestStaleWriterFencesThePool (DPR-089): the API-layer 503 covers requests
// only; the control plane's background writers reach the database through
// the same writer pool. When a promotion elsewhere leaves the writer endpoint
// on a stale ex-primary, the manager must fence that pool read-only, surface
// it on the status view, and release it once the endpoint is the current
// primary again.
func TestStaleWriterFencesThePool(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{InRecovery: false, Epoch: 1, WriterRegion: "us-east"}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 1, WriterRegion: "us-east"}}
	fencer := &fakeFencer{}
	m := NewManager(topo(), writer, reader).WithWriteFencer(fencer)

	m.Refresh(ctx)
	if fencer.on || m.Status().PoolFenced {
		t.Fatal("a healthy writer endpoint must not fence the pool")
	}

	// A promotion elsewhere: the replica already follows epoch 2 while the
	// writer endpoint still resolves to the ex-primary on epoch 1.
	reader.set(Probe{InRecovery: true, Epoch: 2, WriterRegion: "eu-west"})
	m.Refresh(ctx)
	if ok, _ := m.WriterUsable(); ok {
		t.Fatal("stale writer must be fenced at the API layer")
	}
	if !fencer.on {
		t.Fatal("stale writer must fence the pool: background writers would otherwise keep writing to the ex-primary")
	}
	if st := m.Status(); !st.PoolFenced || st.Writer.Role != RoleStale {
		t.Fatalf("status must surface the pool fence on a stale writer: %+v", st)
	}

	// The endpoint moves to the promoted primary: the pool fence lifts on the
	// next probe, no restart required.
	writer.set(Probe{InRecovery: false, Epoch: 2, WriterRegion: "eu-west"})
	m.Refresh(ctx)
	if ok, _ := m.WriterUsable(); !ok {
		t.Fatal("promoted writer must be usable")
	}
	if fencer.on || m.Status().PoolFenced {
		t.Fatal("promoted writer must release the pool fence")
	}
	if len(fencer.calls) != 3 {
		t.Fatalf("the fencer must be told the state on every refresh (idempotently), got %v", fencer.calls)
	}
}

// TestUnreachableAndStandbyWritersLeaveThePoolAlone: an unreachable endpoint
// has no sessions to fence and a standby refuses writes by itself; only the
// stale ex-primary — the node that would happily accept writes — is fenced.
func TestUnreachableAndStandbyWritersLeaveThePoolAlone(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{InRecovery: true, Epoch: 1}}
	fencer := &fakeFencer{}
	m := NewManager(topo(), writer, nil).WithWriteFencer(fencer)
	m.Refresh(ctx)
	writer.set(Probe{Err: context.DeadlineExceeded})
	m.Refresh(ctx)
	if fencer.on || m.Status().PoolFenced {
		t.Fatalf("standby/unreachable endpoints must not fence the pool: %v", fencer.calls)
	}
	if m.Status().PoolFenced {
		t.Fatal("pool fence must stay off")
	}
}

// TestNoFencerKeepsTheAPIFenceOnly: single-region and older wiring without a
// pool fence keep the previous behavior and never report a pool fence.
func TestNoFencerKeepsTheAPIFenceOnly(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{InRecovery: false, Epoch: 1}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 2}}
	m := NewManager(topo(), writer, reader)
	m.Refresh(ctx)
	if ok, _ := m.WriterUsable(); ok {
		t.Fatal("stale writer must still be fenced at the API layer")
	}
	if m.Status().PoolFenced {
		t.Fatal("no fencer attached: pool_fenced must stay false")
	}
}
