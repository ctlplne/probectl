// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func TestPublicVisibilityBaselineQualifiesPeersFromDistinctFullTableCounts(t *testing.T) {
	peerIndex := mrtArchivePeerIndexForTest()
	v4 := mrtRIBForTest(8, false)
	otherV4 := bytes.Clone(v4)
	copy(otherV4[17:20], []byte{198, 51, 100})
	v6 := mrtRIBForTest(10, false)
	source := bytes.Join([][]byte{peerIndex, v4, otherV4, v4, v6}, nil)
	selectPrefixes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	archive := MRTArchiveBudget{ArchiveBytes: int64(len(source)), Records: 5,
		Frame: UpdateFrameBudget{MemoryBytes: 16 << 20, WorkUnits: 16 << 20}}
	policy := PublicVisibilityBaselinePolicy{MinimumIPv4Routes: 2, MinimumIPv6Routes: 2, WorkingBytes: 1 << 20}
	result, err := ReadPublicVisibilityBaseline(t.Context(), bytes.NewReader(source), archive, policy, selectPrefixes)
	if err != nil || len(result.Peers) != 2 || len(result.Projections) != 3 {
		t.Fatalf("the complete public cohort did not produce three projections: %+v, %v", result, err)
	}
	for _, peer := range result.Peers {
		if peer.IPv4Routes != 2 || peer.IPv6Routes != 1 {
			t.Fatal("duplicate RIB entries changed the full-table eligibility counts", peer)
		}
	}
	covered := result.Projections[selectPrefixes[0]].Point()
	absent := result.Projections[selectPrefixes[1]].Point()
	underpopulated := result.Projections[selectPrefixes[2]].Point()
	if !covered.Available || covered.EligiblePeers != 2 || covered.VisiblePeers != 2 ||
		!absent.Available || absent.EligiblePeers != 2 || absent.VisiblePeers != 0 ||
		underpopulated.Available {
		t.Fatalf("missing routes and incomplete peer populations conflated: %+v %+v %+v", covered, absent, underpopulated)
	}
	failed, err := ReadPublicVisibilityBaseline(t.Context(), bytes.NewReader(source[:len(source)-1]), archive, policy, selectPrefixes)
	if !errors.Is(err, errMRTArchiveIncomplete) || len(failed.Projections) != 0 {
		t.Fatal("a partial source produced public visibility", failed, err)
	}
}
