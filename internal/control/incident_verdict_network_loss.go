// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"container/heap"
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
)

type incidentNetworkFailure struct {
	read   store.IncidentTestMeasurement
	target string
}

func incidentCarrierNetworkLoss(ctx context.Context, input incidentVerdictEvidence, item incidentVerdictInterface, after time.Time, seen map[string]incident.VerdictCitation, remaining *int64, hypothesis *incident.VerdictHypothesis) (bool, error) {
	failures := []incidentNetworkFailure{}
	healthy, err := incidentCarrierHTTPSReplies(ctx, input, item, after, seen, remaining, hypothesis)
	if err != nil {
		return false, err
	}
	for _, test := range input.tests {
		source := test.source
		if source.ContextID != item.source.ContextID || source.EntityID != item.source.RouterID || !incidentNetworkTestCurrent(source) {
			continue
		}
		for _, read := range test.reads {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			m := read.ICMP
			if !read.Available || m == nil || m.Version != 1 || m.Canceled || m.IOFailed || !m.ReadComplete || m.StartedAt.Before(after) || m.StartedAt.Before(source.CurrentSince) || m.CompletedAt.Before(m.StartedAt) || !m.CompletedAt.Equal(read.ObservedAt) || !verdictObservationInWindow(read.ObservedAt, input) {
				continue
			}
			if !incidentNetworkTargetOutsideHandoff(read.Alias, item) {
				continue
			}
			citation := testVerdictCitation(read, "")
			fresh, err := admitVerdictOriginal(citation, seen, remaining)
			if err != nil {
				return false, err
			}
			if m.Replies > 0 {
				citation.Reason = "original_configured_external_network_reply"
				if fresh {
					hypothesis.Against = append(hypothesis.Against, citation)
				}
				healthy = true
			} else if m.Requested > 0 && m.Attempted == m.Requested && m.Transmitted == m.Requested && m.SendErrors == 0 {
				citation.Reason = "complete_original_transmitted_external_network_loss"
				if fresh {
					hypothesis.For = append(hypothesis.For, citation)
				}
				failures = append(failures, incidentNetworkFailure{read: read, target: read.Alias})
			}
		}
	}
	if healthy || !independentOverlappingNetworkLoss(failures) {
		hypothesis.Missing = append(hypothesis.Missing, "independent_contemporaneous_complete_external_network_loss")
		return false, nil
	}
	return true, ctx.Err()
}

func incidentNetworkTestCurrent(source store.IncidentConfiguredTest) bool {
	now := time.Now().UTC()
	return source.Type == "icmp" && source.Definition.Type == "icmp" && source.Target == source.Definition.Target && source.AgentID != "" && source.MeasurementIdentityUntil != nil && source.MeasurementIdentityUntil.After(now) && (source.ValidUntil == nil || source.ValidUntil.After(now))
}

func incidentNetworkTargetOutsideHandoff(target string, item incidentVerdictInterface) bool {
	address, err := netip.ParseAddr(target)
	if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || item.roleInputs.SNMP == nil {
		return false
	}
	for _, prefix := range item.roleInputs.SNMP.Prefixes {
		if prefix.Prefix.Contains(address.Unmap()) {
			return false
		}
	}
	return true
}

type networkLossEnding struct {
	index int
	at    time.Time
}
type networkLossHeap []networkLossEnding

func (h networkLossHeap) Len() int           { return len(h) }
func (h networkLossHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h networkLossHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *networkLossHeap) Push(value any)    { *h = append(*h, value.(networkLossEnding)) }
func (h *networkLossHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// A complete interval sweep counts active agents, destinations and their
// intersection. No fixed representative page can hide a different vantage or
// target behind repeated observations from one sender. Touching ends do not
// establish a contemporaneous failure.
func independentOverlappingNetworkLoss(input []incidentNetworkFailure) bool {
	slices.SortFunc(input, func(a, b incidentNetworkFailure) int { return a.read.ICMP.StartedAt.Compare(b.read.ICMP.StartedAt) })
	type pair struct{ agent, target string }
	byAgent, byTarget, byPair := map[string]int{}, map[string]int{}, map[pair]int{}
	active := &networkLossHeap{}
	for index, value := range input {
		start := value.read.ICMP.StartedAt
		if !value.read.ICMP.CompletedAt.After(start) {
			continue
		}
		for active.Len() > 0 && !(*active)[0].at.After(start) {
			ending := heap.Pop(active).(networkLossEnding)
			old := input[ending.index]
			byAgent[old.read.AgentID]--
			byTarget[old.target]--
			byPair[pair{old.read.AgentID, old.target}]--
		}
		key := pair{value.read.AgentID, value.target}
		if active.Len()-byAgent[key.agent]-byTarget[key.target]+byPair[key] > 0 {
			return true
		}
		if value.read.ICMP.CompletedAt.After(start) {
			heap.Push(active, networkLossEnding{index: index, at: value.read.ICMP.CompletedAt})
			byAgent[key.agent]++
			byTarget[key.target]++
			byPair[key]++
		}
	}
	return false
}

// A verified primary HTTP response also proves data reached an external
// service. ICMP filtering cannot override that contradictory observation.
func incidentCarrierHTTPSReplies(ctx context.Context, input incidentVerdictEvidence, item incidentVerdictInterface, after time.Time, seen map[string]incident.VerdictCitation, remaining *int64, hypothesis *incident.VerdictHypothesis) (bool, error) {
	reachable := false
	for _, test := range input.tests {
		if test.source.ContextID != item.source.ContextID || test.source.EntityID != item.source.RouterID {
			continue
		}
		if _, ok := incidentVerdictHTTPSOrigin(test.source); !ok {
			continue
		}
		for _, read := range test.reads {
			m := read.Outcome
			if !read.Available || m == nil || m.Version != 2 || m.CanaryType != "http" || m.Canceled || m.HTTPResponse == nil || !m.HTTPResponse.TLSVerified || !m.HTTPResponse.SameOrigin || m.StartedAt.Before(after) || m.StartedAt.Before(test.source.CurrentSince) || !m.CompletedAt.Equal(read.ObservedAt) || !verdictObservationInWindow(read.ObservedAt, input) {
				continue
			}
			citation := testVerdictCitation(read, "original_verified_primary_https_network_reply")
			if _, err := admitVerdictOriginal(citation, seen, remaining); err != nil {
				return false, err
			}
			hypothesis.Against = append(hypothesis.Against, citation)
			reachable = true
		}
	}
	return reachable, ctx.Err()
}
