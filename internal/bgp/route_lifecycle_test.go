// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"testing"
)

func TestRoutingLifecycleRequiresCompleteMatchingSourceFrame(t *testing.T) {
	open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1}, false)
	up := peerUpFrameForTest(open, open, nil)
	up[6] = 3
	clear(up[16:32])
	clear(up[48:68])
	peer, err := parseBMPPeerUp(t.Context(), up, PeerMessageBudget{1 << 20, 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	stats := append([]byte(nil), up[:48]...)
	stats[5] = 1
	stats = append(stats, 0, 0, 0, 1, 255, 251, 0, 3, 0, 255, 0)
	binary.BigEndian.PutUint32(stats[1:5], uint32(len(stats)))
	profile := PeerMessageBudget{1 << 20, 1 << 20}
	if reset, err := DecodeRoutingLifecycle(t.Context(), stats, peer, profile); err != nil || reset {
		t.Fatal("complete source liveness with opaque statistics was lost", reset, err)
	}
	down := append([]byte(nil), up[:48]...)
	down[5] = 2
	down = append(down, 6)
	binary.BigEndian.PutUint32(down[1:5], uint32(len(down)))
	if reset, err := DecodeRoutingLifecycle(t.Context(), down, peer, profile); err != nil || !reset {
		t.Fatal("complete Loc-RIB reset was lost", reset, err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { b[51] = 0; return b },
		func(b []byte) []byte { b[52], b[53] = 0, 8; return b },
		func(b []byte) []byte { b[53] = 255; return b },
		func(b []byte) []byte { b[51]++; return b },
		func(b []byte) []byte { b[55]++; return b },
		func(b []byte) []byte { b[8] = 1; return b },
		func(b []byte) []byte { b[36]++; return b },
		func(b []byte) []byte { b[5] = 0; return b },
		func(b []byte) []byte { return b[:len(b)-1] },
	} {
		if reset, err := DecodeRoutingLifecycle(t.Context(), mutate(append([]byte(nil), stats...)), peer, profile); err == nil || reset {
			t.Fatal("incomplete or foreign lifecycle frame refreshed source authority")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if reset, err := DecodeRoutingLifecycle(ctx, stats, peer, profile); err == nil || reset {
		t.Fatal("canceled lifecycle admitted a source observation")
	}
	if reset, err := DecodeRoutingLifecycle(t.Context(), stats, peer, PeerMessageBudget{1, 1}); err == nil || reset {
		t.Fatal("unadmitted lifecycle admitted a source observation")
	}
}
