// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"encoding/hex"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestPhysicalPeerSessionKeepsObservedKindsAndOriginalDigest(t *testing.T) {
	budget := PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	for _, tc := range []struct {
		raw   []byte
		state string
	}{
		{observedPeerUpFrame(t, "2001:db8::7", 4294967295), "up"},
		{peerDownFrameForTest(1, peerDownNotificationForTest(), false), "down"},
		{peerDownFrameForTest(2, []byte{255, 255}, false), "down"},
		{peerDownFrameForTest(3, peerDownNotificationForTest(), false), "down"},
		{peerDownFrameForTest(4, nil, false), "down"},
		{peerDownFrameForTest(5, nil, false), "monitoring_withdrawn"},
	} {
		got, err := DecodePhysicalPeerSession(t.Context(), tc.raw, budget)
		if err != nil || got == nil {
			t.Fatal("whole physical lifecycle frame was lost", tc.state, err)
		}
		if got.State != tc.state || got.FrameDigest != hex.EncodeToString(crypto.Hash(tc.raw)) || got.Validate() != nil {
			t.Fatal("lifecycle kind, complete frame digest or shape changed")
		}
		if tc.state == "monitoring_withdrawn" && (got.DownReason == nil || *got.DownReason != 5) {
			t.Fatal("monitoring withdrawal became an inferred failure")
		}
		clear(tc.raw)
		if got.Validate() != nil {
			t.Fatal("typed record retained mutable source bytes")
		}
	}
	if got, err := DecodePhysicalPeerSession(t.Context(), peerDownFrameForTest(6, nil, true), budget); err == nil || got != nil {
		t.Fatal("Loc-RIB lifecycle became a physical neighbor fact")
	}
}
