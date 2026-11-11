// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import "context"

const (
	PeeringPathEligible    = "eligible"
	PeeringPathNotOnPath   = "not_on_path"
	PeeringPathAmbiguous   = "ambiguous"
	PeeringPathUnavailable = "unavailable"
)

// PeeringPathMatch describes observed path evidence, not a forwarding promise,
// an existing peering session or permission to read any tenant/source.
type PeeringPathMatch struct {
	State string
	Paths int
}

// MatchPeeringPaths checks every original path before making one eligibility
// decision. Prepends do not multiply traffic. An unordered AS_SET alone cannot
// establish the peer's position; confederation members are not public peers.
// Different selected paths must agree. Callers own current tenant/source
// authorization, FX4 transit roles and exact IX/LAN membership separately.
func MatchPeeringPaths(ctx context.Context, peer uint32, paths [][]ASPathSegment, budget ASPathParseBudget) (PeeringPathMatch, error) {
	none := PeeringPathMatch{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if peer == 0 {
		return none, ErrASPathSyntax
	}
	if budget.MemoryBytes < 128 || budget.WorkUnits <= 0 || int64(len(paths)) > budget.WorkUnits/4 {
		return none, ErrASPathBudget
	}
	work := budget.WorkUnits - int64(len(paths))*4
	// Validate the complete admitted input first. An early matching ASN cannot
	// make a malformed or over-budget late path disappear from the operation.
	for _, path := range paths {
		for _, segment := range path {
			if err := ctx.Err(); err != nil {
				return none, err
			}
			if segment.Kind < ASPathSet || segment.Kind > ASPathConfedSet || len(segment.Values) == 0 {
				return none, ErrASPathSyntax
			}
			if work < 4 || int64(len(segment.Values)) > (work-4)/4 {
				return none, ErrASPathBudget
			}
			work -= 4 + int64(len(segment.Values))*4
		}
	}
	if len(paths) == 0 {
		return PeeringPathMatch{State: PeeringPathUnavailable}, nil
	}
	consensus := ""
	for _, path := range paths {
		ordered, unordered := false, false
		for _, segment := range path {
			for _, asn := range segment.Values {
				if err := ctx.Err(); err != nil {
					return none, err
				}
				if asn != peer {
					continue
				}
				switch segment.Kind {
				case ASPathSequence:
					ordered = true
				case ASPathSet:
					unordered = true
				}
			}
		}
		state := PeeringPathNotOnPath
		if ordered {
			state = PeeringPathEligible
		} else if unordered {
			state = PeeringPathAmbiguous
		}
		if consensus == "" {
			consensus = state
		} else if consensus != state {
			consensus = PeeringPathAmbiguous
		}
	}
	return PeeringPathMatch{State: consensus, Paths: len(paths)}, nil
}
