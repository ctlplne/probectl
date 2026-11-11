// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"errors"
	"testing"
)

func TestPeeringPathsKeepFullASNOrderedMembershipAndAllPathConsensus(t *testing.T) {
	const peer = ^uint32(0)
	sequence := func(asns ...uint32) []ASPathSegment {
		return []ASPathSegment{{Kind: ASPathSequence, Values: asns}}
	}
	budget := ASPathParseBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	for name, test := range map[string]struct {
		paths [][]ASPathSegment
		state string
	}{
		"origin":        {[][]ASPathSegment{sequence(64496, peer)}, PeeringPathEligible},
		"prepends":      {[][]ASPathSegment{sequence(peer, peer, 64496), sequence(64500, peer)}, PeeringPathEligible},
		"absent":        {[][]ASPathSegment{sequence(64496, 64500)}, PeeringPathNotOnPath},
		"empty-path":    {[][]ASPathSegment{{}}, PeeringPathNotOnPath},
		"missing":       {nil, PeeringPathUnavailable},
		"set":           {[][]ASPathSegment{{{Kind: ASPathSet, Values: []uint32{peer, 64496}}}}, PeeringPathAmbiguous},
		"confed-only":   {[][]ASPathSegment{{{Kind: ASPathConfedSequence, Values: []uint32{peer}}, {Kind: ASPathSequence, Values: []uint32{64496}}}}, PeeringPathNotOnPath},
		"ordered-set":   {[][]ASPathSegment{{{Kind: ASPathSet, Values: []uint32{peer}}, {Kind: ASPathSequence, Values: []uint32{peer}}}}, PeeringPathEligible},
		"mixed-paths":   {[][]ASPathSegment{sequence(peer), sequence(64496)}, PeeringPathAmbiguous},
		"mixed-set":     {[][]ASPathSegment{sequence(peer), {{Kind: ASPathSet, Values: []uint32{peer}}}}, PeeringPathAmbiguous},
		"ambiguous-all": {[][]ASPathSegment{{{Kind: ASPathSet, Values: []uint32{peer}}}, {{Kind: ASPathSet, Values: []uint32{peer}}}}, PeeringPathAmbiguous},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := MatchPeeringPaths(t.Context(), peer, test.paths, budget)
			if err != nil || got.State != test.state || got.Paths != len(test.paths) {
				t.Fatal("peering path eligibility flattened unordered/confederation data or ignored another original path", got, err)
			}
		})
	}
	// Preserve a complete long path and late candidate beyond former short
	// display widths. This model carries no protocol/display population cap.
	values := make([]uint32, 65538)
	for i := range values {
		values[i] = 64496
	}
	values[len(values)-1] = peer
	got, err := MatchPeeringPaths(t.Context(), peer, [][]ASPathSegment{sequence(values...)}, budget)
	if err != nil || got.State != PeeringPathEligible || values[len(values)-1] != peer {
		t.Fatal("peering path eligibility clipped or mutated the complete original path", got, err)
	}
}

func TestPeeringPathsRefuseMalformedLateUnadmittedAndCanceledEvidence(t *testing.T) {
	paths := [][]ASPathSegment{{{Kind: ASPathSequence, Values: []uint32{64500}}}, {{Kind: 9, Values: []uint32{64500}}}}
	budget := ASPathParseBudget{MemoryBytes: 1024, WorkUnits: 1024}
	if got, err := MatchPeeringPaths(t.Context(), 64500, paths, budget); !errors.Is(err, ErrASPathSyntax) || got.State != "" {
		t.Fatal("matching first path hid malformed late peering evidence", got, err)
	}
	paths = paths[:1]
	for _, tiny := range []ASPathParseBudget{{MemoryBytes: 127, WorkUnits: 1024}, {MemoryBytes: 1024, WorkUnits: 7}} {
		if got, err := MatchPeeringPaths(t.Context(), 64500, paths, tiny); !errors.Is(err, ErrASPathBudget) || got.State != "" {
			t.Fatal("peering path evidence bypassed whole-operation admission", got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := MatchPeeringPaths(ctx, 64500, paths, budget); !errors.Is(err, context.Canceled) || got.State != "" {
		t.Fatal("canceled peering evidence returned an eligibility decision", got, err)
	}
}
