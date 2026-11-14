// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
)

// A positive routing error is separate from silence, filtering and an app
// failure. Its current selected-prefix origin is context, not forwarding proof.
func classifyIncidentInternet(ctx context.Context, input incidentVerdictEvidence, seen map[string]incident.VerdictCitation, remaining *int64, hypothesis *incident.VerdictHypothesis) (bool, error) {
	proven := false
	for _, handoff := range input.interfaces {
		if (!handoff.direct && !handoff.incidentRouter) || !handoff.source.Current || handoff.role.Role != interfaceRoleTransit || !handoff.role.SNMPCurrent || !handoff.role.PrefixCurrent {
			continue
		}
		for _, peer := range handoff.peerReads {
			if peer.Session == nil || peer.Session.State != "up" || !verdictObservationInWindow(peer.ObservedAt, input) {
				continue
			}
			citation, owned, err := incidentCarrierPeerCitation(ctx, handoff, peer, remaining)
			if err != nil {
				return false, err
			}
			if !owned {
				continue
			}
			charge := int64(len(peer.Session.RawFrame))*256 + 4096
			if charge > *remaining {
				return false, store.ErrIncidentImpactBudget
			}
			*remaining -= charge
			asns, err := bgp.PhysicalPeerOpenASNs(ctx, peer.Session.RawFrame, bgp.PeerMessageBudget{MemoryBytes: charge, WorkUnits: charge})
			if err != nil || asns.Remote != peer.Session.PeerASN || asns.Local == asns.Remote {
				continue
			}
			if incidentInternetPeerConflict(handoff.peerReads, peer, input) {
				continue
			}
			healthy, err := incidentCarrierHandoffState(ctx, handoff, input, peer.ObservedAt, seen, remaining, hypothesis)
			if err != nil {
				return false, err
			}
			local, err := incidentCarrierLocalCoverage(ctx, input, handoff, peer.ObservedAt, seen, remaining, hypothesis)
			if err != nil {
				return false, err
			}
			failures, contrary, err := incidentInternetNetworkErrors(ctx, input, handoff, peer, asns, seen, remaining, hypothesis)
			if err != nil {
				return false, err
			}
			if !healthy || !local || contrary || !independentOverlappingNetworkLoss(failures) {
				continue
			}
			citation.Reason = "original_healthy_physical_provider_session"
			if _, err := admitVerdictOriginal(citation, seen, remaining); err != nil {
				return false, err
			}
			hypothesis.For = append(hypothesis.For, citation)
			proven = true
		}
	}
	if proven {
		hypothesis.Confidence = "corroborated"
	} else {
		hypothesis.Missing = append(hypothesis.Missing, "independent_original_external_routing_errors_with_current_owned_as_context")
	}
	return proven, ctx.Err()
}

func incidentInternetPeerConflict(reads []store.IncidentPeerSessionMeasurement, peer store.IncidentPeerSessionMeasurement, input incidentVerdictEvidence) bool {
	for _, other := range reads {
		if !verdictObservationInWindow(other.ObservedAt, input) || other.ObservedAt.Before(peer.ObservedAt) {
			continue
		}
		if !other.SourceCurrent || other.Session == nil {
			return true
		}
		if other.Session.PeerAddress != peer.Session.PeerAddress || other.Session.PeerASN != peer.Session.PeerASN {
			continue
		}
		if !other.SourceCurrent || other.Session.State != "up" {
			return true
		}
	}
	return false
}

func incidentInternetNetworkErrors(ctx context.Context, input incidentVerdictEvidence, handoff incidentVerdictInterface, peer store.IncidentPeerSessionMeasurement, asns bgp.PhysicalPeerASNs, seen map[string]incident.VerdictCitation, remaining *int64, hypothesis *incident.VerdictHypothesis) ([]incidentNetworkFailure, bool, error) {
	failures := []incidentNetworkFailure{}
	contrary, err := incidentCarrierHTTPSReplies(ctx, input, handoff, peer.ObservedAt, seen, remaining, hypothesis)
	if err != nil {
		return nil, false, err
	}
	for _, test := range input.tests {
		if test.source.ContextID != handoff.source.ContextID || test.source.EntityID != handoff.source.RouterID || !incidentNetworkTestCurrent(test.source) {
			continue
		}
		for _, read := range test.reads {
			if err := ctx.Err(); err != nil {
				return nil, false, err
			}
			m := read.ICMP
			if !read.Available || m == nil || m.Canceled || m.IOFailed || !m.ReadComplete || m.StartedAt.Before(peer.ObservedAt) || m.StartedAt.Before(test.source.CurrentSince) || !icmpCompletionMatchesIndex(m, read.ObservedAt) || !verdictObservationInWindow(read.ObservedAt, input) || !incidentNetworkTargetOutsideHandoff(read.Alias, handoff) {
				continue
			}
			citation := testVerdictCitation(read, "")
			if m.Replies > 0 {
				contrary = true
				citation.Reason = "original_configured_external_network_reply"
				fresh, err := admitVerdictOriginal(citation, seen, remaining)
				if err != nil {
					return nil, false, err
				}
				if fresh {
					hypothesis.Against = append(hypothesis.Against, citation)
				}
				continue
			}
			if (m.Version != 2 && m.Version != 3) || m.Requested == 0 || m.Attempted != m.Requested || m.Transmitted != m.Requested || m.SendErrors != 0 || uint64(len(m.NetworkErrors)) != uint64(m.Transmitted) {
				continue
			}
			routes := map[incidentVerdictRouteKey]incident.VerdictCitation{}
			complete := true
			for _, outcome := range m.NetworkErrors {
				if err := ctx.Err(); err != nil {
					return nil, false, err
				}
				if *remaining < 64 {
					return nil, false, store.ErrIncidentImpactBudget
				}
				*remaining -= 64
				if outcome.Conflicting || outcome.Code != 0 || outcome.Type != 1 && outcome.Type != 3 || outcome.Responder == read.Alias || !incidentNetworkTargetOutsideHandoff(outcome.Responder, handoff) {
					complete = false
					continue
				}
				key := incidentVerdictRouteKey{ContextID: read.ContextID, RouterID: read.EntityID, Address: outcome.Responder}
				route, ok := input.routes[key]
				address, addressErr := netip.ParseAddr(outcome.Responder)
				if !ok || route.Route == nil || addressErr != nil || !route.Route.Prefix.Contains(address) || route.Route.Source.ObservedAt.After(outcome.ReceivedAt) || route.Route.LastObservedAt.After(outcome.ReceivedAt) {
					complete = false
					continue
				}
				if _, checked := routes[key]; checked {
					continue
				}
				origin, ok, err := incidentInternetRouteOrigin(ctx, *route.Route, handoff, asns, remaining)
				if err != nil {
					return nil, false, err
				}
				if !ok {
					complete = false
					continue
				}
				r := route.Route
				routes[key] = incident.VerdictCitation{ContextID: read.ContextID, EntityID: read.EntityID, SourceKind: "router_bgp", AgentID: r.Source.CollectorAgentID, Digest: route.Digest, ObservedAt: r.LastObservedAt,
					Routing: &incident.VerdictRoutingReference{ViewID: r.View.ID, GenerationID: r.View.Generation, Sequence: strconv.FormatInt(r.LastSequence, 10), Prefix: r.Prefix.String(), Address: outcome.Responder, OriginASN: origin}, Reason: "current_selected_prefix_origin_beyond_declared_provider_not_forwarding_proof"}
			}
			if !complete {
				continue
			}
			citation.Reason = "complete_original_challenge_matched_external_no_route_errors"
			fresh, err := admitVerdictOriginal(citation, seen, remaining)
			if err != nil {
				return nil, false, err
			}
			if fresh {
				hypothesis.For = append(hypothesis.For, citation)
			}
			for _, route := range routes {
				fresh, err := admitVerdictOriginal(route, seen, remaining)
				if err != nil {
					return nil, false, err
				}
				if fresh {
					hypothesis.For = append(hypothesis.For, route)
				}
			}
			failures = append(failures, incidentNetworkFailure{read: read, target: read.Alias})
		}
	}
	return failures, contrary, ctx.Err()
}

func incidentInternetRouteOrigin(ctx context.Context, route store.BGPRoutingLookup, handoff incidentVerdictInterface, asns bgp.PhysicalPeerASNs, remaining *int64) (uint32, bool, error) {
	if !route.ValidUntil.After(time.Now().UTC()) || route.Prefix.Bits() <= 0 || len(route.Paths) == 0 {
		return 0, false, nil
	}
	origin := uint32(0)
	for _, path := range route.Paths {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		segments := make([]bgp.ASPathSegment, 0, len(path.Segments))
		for _, segment := range path.Segments {
			charge := int64(128 + len(segment.Values)*64)
			if charge > *remaining {
				return 0, false, store.ErrIncidentImpactBudget
			}
			*remaining -= charge
			segments = append(segments, bgp.ASPathSegment{Kind: bgp.ASPathSegmentKind(segment.Kind), Values: segment.Values})
		}
		fields, err := bgp.ProjectRoutingPathFields(ctx, segments, bgp.ASPathParseBudget{MemoryBytes: *remaining, WorkUnits: *remaining})
		if err != nil {
			return 0, false, err
		}
		if fields.OriginAS == nil || fields.FirstTransitAS == nil || *fields.FirstTransitAS != asns.Remote || *fields.OriginAS == 0 || *fields.OriginAS == asns.Local || slices.Contains(handoff.roleInputs.Policy.Definition.ProviderASNs, *fields.OriginAS) || slices.Contains(handoff.roleInputs.Policy.Definition.CustomerASNs, *fields.OriginAS) {
			return 0, false, nil
		}
		if origin != 0 && origin != *fields.OriginAS {
			return 0, false, nil
		}
		origin = *fields.OriginAS
	}
	return origin, origin != 0, ctx.Err()
}
