// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

// Captured from the digest-pinned FRR10.3.1 lab's actual Loc-RIB feed. Its
// fabricated OPEN advertises ADD-PATH with zero tuples. Retain the full frame:
// strict defaults must not infer ordinary NLRI from invalid encoding metadata.
// A separately configured serializer profile has its own explicit source contract.
const frr103LocRIBPeerUp = "03000000f80303000000000000000000000000000000000000000000000000000000fc590ae7201f6aec229f000246370000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff00550104000000b4000000003802020200020246000206410400000000020206000202450002024c000210490e0c6434653834663539316438380002044002c07802024700ffffffffffffffffffffffffffffffff00550104000000b4000000003802020200020246000206410400000000020206000202450002024c000210490e0c6434653834663539316438380002044002c0780202470000030006676c6f62616c"

func TestBMPPeerUpPreservesMalformedRealSourceCapabilityDiagnosis(t *testing.T) {
	raw, err := hex.DecodeString(frr103LocRIBPeerUp)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := parseBMPPeerUp(t.Context(), raw, PeerMessageBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20})
	if !errors.Is(err, ErrBMPPeerUp) || !errors.Is(err, ErrRouteCapabilities) || !reflect.DeepEqual(peer, PeerUp{}) {
		t.Fatal("malformed real source lost capability diagnosis or exposed partial peer state", err)
	}
}
