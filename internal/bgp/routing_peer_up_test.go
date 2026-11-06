// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"reflect"
	"testing"
)

func TestRoutingPeerUpKeepsCompleteDeclaredFamiliesAndRefusesMalformedSource(t *testing.T) {
	open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 1, 4, 0, 2, 0, 1}, false)
	raw := peerUpFrameForTest(open, open, nil)
	got, families, err := DecodeRoutingPeerUp(t.Context(), raw, PeerMessageBudget{16 << 20, 16 << 20})
	if err != nil || !reflect.DeepEqual(families, []RouteFamily{{AFI: 1, SAFI: 1}, {AFI: 2, SAFI: 1}}) || !reflect.DeepEqual(got.SentOpen, open) {
		t.Fatal("complete routing peer lost original metadata or declared families", err)
	}
	for _, bad := range [][]byte{nil, raw[:len(raw)-1], peerUpFrameForTest(routeOpenForTest([]byte{69, 0}, false), open, nil)} {
		got, families, err := DecodeRoutingPeerUp(t.Context(), bad, PeerMessageBudget{16 << 20, 16 << 20})
		if err == nil || !reflect.DeepEqual(got, PeerUp{}) || families != nil {
			t.Fatal("malformed routing source exposed partial metadata or families", err)
		}
	}
}
