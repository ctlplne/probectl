// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"errors"
)

// ASPathAttributes contains source-proven ASN encoding and the two relevant
// aggregation attributes. The caller must validate their wire framing and
// the BMP view/capabilities; the decoder never guesses these from path bytes.
type ASPathAttributes struct {
	FourOctetSession                        bool
	Path, AS4Path                           []byte // nil means the attribute is absent
	AggregatorPresent, AS4AggregatorPresent bool
	AggregatorASN                           uint32
}

// ASPathReconstruction records how RFC6793 attributes were interpreted. A
// reconstructed reported path is not a selected route or forwarding proof.
type ASPathReconstruction struct {
	Segments                   []ASPathSegment
	AS4Action                  string
	AS4ConfederationsDiscarded bool
}

// ReconstructASPath follows RFC6793 section4.2.3 without flattening AS sets or
// confederations. Source attributes are immutable; output owns its values.
// Invalid optional AS4_PATH is discarded with explicit provenance. Malformed
// AS_PATH, cancellation and operation admission errors refuse all output.
func ReconstructASPath(ctx context.Context, input ASPathAttributes, budget ASPathParseBudget) (ASPathReconstruction, error) {
	none := ASPathReconstruction{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	// Nil means the mandatory attribute is absent. A present empty AS_PATH
	// is represented by a non-nil empty slice and remains a valid empty path.
	if input.Path == nil {
		return none, ErrASPathSyntax
	}
	width := 2
	if input.FourOctetSession {
		width = 4
	}
	legacy, err := ParseASPathSegments(ctx, input.Path, width, budget)
	if err != nil {
		return none, err
	}
	left, err := remainingASPathAdmission(budget, legacy, int64(len(input.Path))*2)
	if err != nil {
		return none, err
	}
	out := ASPathReconstruction{Segments: legacy, AS4Action: "absent"}
	if input.AS4Path == nil {
		return out, nil
	}
	if input.FourOctetSession {
		out.AS4Action = "ignored_four_octet_session"
		return out, nil
	}
	const asTrans = 23456
	if input.AggregatorPresent && input.AS4AggregatorPresent && input.AggregatorASN != asTrans {
		out.AS4Action = "ignored_legacy_aggregation"
		return out, nil
	}
	if len(input.AS4Path) < 6 || len(input.AS4Path)%2 != 0 {
		out.AS4Action = "ignored_malformed"
		return out, nil
	}
	extended, err := ParseASPathSegments(ctx, input.AS4Path, 4, left)
	if err != nil {
		if errors.Is(err, ErrASPathSyntax) {
			out.AS4Action = "ignored_malformed"
			return out, nil
		}
		return none, err
	}
	left, err = remainingASPathAdmission(left, extended, int64(len(input.AS4Path))*2)
	if err != nil {
		return none, err
	}
	// RFC6793 discards confederation segments in optional AS4_PATH while
	// preserving valid confederations adjoining the retained legacy prefix.
	filtered := extended[:0]
	for _, segment := range extended {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if segment.Kind == ASPathConfedSequence || segment.Kind == ASPathConfedSet {
			out.AS4ConfederationsDiscarded = true
			continue
		}
		filtered = append(filtered, segment)
	}
	extended = filtered
	oldLength, newLength := asPathSelectionLength(legacy), asPathSelectionLength(extended)
	if oldLength < newLength {
		out.AS4Action = "ignored_longer_than_legacy"
		return out, nil
	}
	// Charge the new segment headers BEFORE allocation; ASN storage is
	// already owned/charged by the two parsers and is reused, not cloned.
	maximumSegments := len(legacy) + len(extended)
	if int64(maximumSegments) > left.MemoryBytes/32 {
		return none, ErrASPathBudget
	}
	if int64(len(legacy)+len(extended)) > left.WorkUnits {
		return none, ErrASPathBudget
	}
	result := make([]ASPathSegment, 0, maximumSegments)
	keep := oldLength - newLength
	for _, segment := range legacy {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if segment.Kind == ASPathConfedSequence || segment.Kind == ASPathConfedSet {
			result = append(result, segment)
			continue
		}
		if keep == 0 {
			break
		}
		if segment.Kind == ASPathSet {
			result = append(result, segment)
			keep--
			continue
		}
		take := min(keep, int64(len(segment.Values)))
		values := segment.Values[:int(take):int(take)]
		result = append(result, ASPathSegment{Kind: segment.Kind, Values: values})
		keep -= take
		if take < int64(len(segment.Values)) {
			break
		}
	}
	result = append(result, extended...)
	if err := ctx.Err(); err != nil {
		return none, err
	}
	out.Segments, out.AS4Action = result, "reconstructed"
	return out, nil
}

func asPathSelectionLength(path []ASPathSegment) int64 {
	var count int64
	for _, segment := range path {
		switch segment.Kind {
		case ASPathSet:
			count++
		case ASPathSequence:
			count += int64(len(segment.Values))
		}
	}
	return count
}

func remainingASPathAdmission(budget ASPathParseBudget, path []ASPathSegment, work int64) (ASPathParseBudget, error) {
	if work < 0 || work > budget.WorkUnits {
		return ASPathParseBudget{}, ErrASPathBudget
	}
	budget.WorkUnits -= work
	for _, segment := range path {
		if budget.MemoryBytes < 32 || int64(len(segment.Values)) > (budget.MemoryBytes-32)/4 {
			return ASPathParseBudget{}, ErrASPathBudget
		}
		budget.MemoryBytes -= 32 + int64(len(segment.Values))*4
	}
	return budget, nil
}
