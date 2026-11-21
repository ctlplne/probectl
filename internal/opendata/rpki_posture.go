// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"net/netip"
	"slices"
	"time"
)

// RPKIPosture retains the local validator's original generation and the
// complete set of covering assertions for a source observation.
type RPKIPosture struct {
	Status              string                `json:"status"`
	Reason              string                `json:"reason"`
	ValidatorVersion    string                `json:"validator_version,omitempty"`
	ValidatorObservedAt *time.Time            `json:"validator_observed_at,omitempty"`
	Covering            []RPKIVRP             `json:"covering"`
	Suggestion          *MinimalROASuggestion `json:"suggestion,omitempty"`
}

// MinimalROASuggestion lists the one observed prefix exactly. Leaving
// maxLength absent gives it the original prefix length per RFC 9582.
type MinimalROASuggestion struct {
	Prefix    netip.Prefix `json:"prefix"`
	OriginASN uint32       `json:"origin_asn"`
}

// AssessRPKIPosture evaluates an already authorized routing observation.
// allowExactSuggestion comes from the caller's owned origin policy; a BGP
// path or covering ROA is never authority to create a tenant suggestion.
func AssessRPKIPosture(ctx context.Context, snapshot RPKISnapshot, at time.Time, prefix netip.Prefix, origin *uint32,
	allowExactSuggestion bool, memoryBytes, workUnits int64) (RPKIPosture, error) {
	out := RPKIPosture{Status: "unknown", Reason: "validator_unavailable", Covering: []RPKIVRP{}}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if !snapshot.UsableAt(at) {
		return out, nil
	}
	status, covering, err := snapshot.Validate(ctx, prefix, origin, memoryBytes, workUnits)
	if err != nil {
		return out, err
	}
	out.ValidatorVersion = snapshot.Version
	out.ValidatorObservedAt = &snapshot.ObservedAt
	out.Status = status
	out.Reason = rpkiPostureReason(prefix, origin, status, covering)
	if covering != nil {
		out.Covering = covering
	}
	denialPresent := slices.ContainsFunc(covering, func(assertion RPKIVRP) bool { return assertion.ASN == 0 })
	if allowExactSuggestion && origin != nil && !denialPresent && (out.Status == "invalid" || out.Status == "not_found") {
		out.Suggestion = &MinimalROASuggestion{Prefix: prefix, OriginASN: *origin}
	}
	return out, ctx.Err()
}

func rpkiPostureReason(prefix netip.Prefix, origin *uint32, status string, covering []RPKIVRP) string {
	switch status {
	case "valid":
		return "matching_prefix_and_origin"
	case "not_found":
		return "no_covering_assertion"
	case "invalid":
		var originMatch, lengthMatch, as0 bool
		for _, row := range covering {
			originMatch = originMatch || row.ASN == *origin
			lengthMatch = lengthMatch || row.ASN != 0 && row.MaxLength >= prefix.Bits()
			as0 = as0 || row.ASN == 0
		}
		switch {
		case originMatch:
			return "prefix_length_exceeds_origin_authorization"
		case lengthMatch:
			return "origin_mismatch"
		case as0:
			return "as0_denial_or_insufficient_length"
		default:
			return "origin_and_length_mismatch"
		}
	default:
		return "origin_unavailable"
	}
}
