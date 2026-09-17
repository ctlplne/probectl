// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cluster

import (
	"context"
	"testing"
	"time"
)

// hangingProbe never answers until its context ends — a pooled session whose
// peer vanished without a RST.
type hangingProbe struct{}

func (hangingProbe) Probe(ctx context.Context) Probe {
	<-ctx.Done()
	return Probe{Err: ctx.Err()}
}

// TestHungProbeIsBoundedAndFencesWrites (DPR-095): on the lab a lost primary
// left the writer probe blocked for ~2 minutes, and writes were fenced only
// then. A hung probe must fail within the probe deadline and fence writes.
func TestHungProbeIsBoundedAndFencesWrites(t *testing.T) {
	m := NewManager(topo(), hangingProbe{}, nil).WithProbeTimeout(50 * time.Millisecond)
	start := time.Now()
	m.Refresh(context.Background())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("refresh must return within the probe deadline, took %s", elapsed)
	}
	if ok, reason := m.WriterUsable(); ok || reason == "" {
		t.Fatalf("a hung writer probe must fence writes, got ok=%v reason=%q", ok, reason)
	}
	if st := m.Status(); st.Writer.Role != RoleUnknown {
		t.Fatalf("hung probe must classify the writer unknown, got %+v", st.Writer)
	}
}

// TestProbeTimeoutDefaultsAndOverride: the default is one probe interval and a
// non-positive override keeps it.
func TestProbeTimeoutDefaultsAndOverride(t *testing.T) {
	m := NewManager(topo(), &fakeProbe{}, nil)
	if m.probeTimeout != DefaultProbeTimeout {
		t.Fatalf("default probe timeout = %s", m.probeTimeout)
	}
	if m.WithProbeTimeout(0).probeTimeout != DefaultProbeTimeout {
		t.Fatal("non-positive override must keep the default")
	}
	if m.WithProbeTimeout(time.Second).probeTimeout != time.Second {
		t.Fatal("override not applied")
	}
}
