// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
)

// Duplicate originals cannot create independent corroboration or contradict
// themselves. This compares the immutable digest and all public source keys;
// final source readers still recheck the digest against the stored document.
func admitVerdictOriginal(citation incident.VerdictCitation, seen map[string]incident.VerdictCitation, remaining *int64) (bool, error) {
	key, err := citation.SourceReference()
	if err != nil || citation.AgentID == "" || citation.ContextID == "" || citation.EntityID == "" || citation.Digest == strings.Repeat("0", 64) {
		return false, errIncidentVerdictInput
	}
	identity := citation
	identity.Reason = ""
	if old, found := seen[key]; found {
		if old.Routing != nil && identity.Routing != nil {
			if *old.Routing != *identity.Routing {
				return false, errIncidentVerdictInput
			}
			old.Routing, identity.Routing = nil, nil
		}
		if old != identity {
			return false, errIncidentVerdictInput
		}
		return false, nil
	}
	if err := chargeVerdictCitation(remaining, citation); err != nil {
		return false, err
	}
	seen[key] = identity
	return true, nil
}

func classifyIncidentLocalInterfaces(ctx context.Context, input incidentVerdictEvidence, seen map[string]incident.VerdictCitation, remaining *int64, hypothesis *incident.VerdictHypothesis) (bool, error) {
	proven := false
	for _, item := range input.interfaces {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if !item.direct || !item.source.Current || item.source.ValidUntil != nil && !item.source.ValidUntil.After(time.Now().UTC()) || !item.role.SNMPCurrent || item.role.Role != interfaceRoleBackbone {
			continue // A transit hand-off is not proof that the carrier failed.
		}
		down, up, unavailable := false, false, false
		for _, read := range item.reads {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if !verdictObservationInWindow(read.ObservedAt, input) {
				continue
			}
			citation := interfaceVerdictCitation(read, "")
			fresh, err := admitVerdictOriginal(citation, seen, remaining)
			if err != nil {
				return false, err
			}
			if !fresh {
				continue
			}
			if !read.Available || !read.OriginalSenderValid || read.ObservedAt.Before(item.source.CurrentSince) || read.State == nil || read.State.Version != 1 || read.State.OperStatus == nil || read.State.AdminStatus == nil {
				unavailable = true
				continue
			}
			oper, admin := *read.State.OperStatus, *read.State.AdminStatus
			switch {
			case admin == 1 && (oper == 2 || oper == 7):
				citation.Reason = "original_admin_up_oper_down_local_interface"
				hypothesis.For = append(hypothesis.For, citation)
				down = true
			case oper == 1:
				citation.Reason = "original_local_interface_oper_up"
				hypothesis.Against = append(hypothesis.Against, citation)
				up = true
			default:
				// Testing, dormant, missing hardware and unknown states do not
				// establish an unplanned outage. Admin-down is intentional.
				unavailable = true
			}
		}
		if unavailable {
			hypothesis.Missing = append(hypothesis.Missing, "complete_original_interface_state_in_window")
		}
		proven = proven || down && !up && !unavailable
	}
	if proven {
		hypothesis.Confidence = "direct"
	} else {
		hypothesis.Missing = append(hypothesis.Missing, "unambiguous_direct_local_interface_failure")
	}
	return proven, ctx.Err()
}

type incidentRemoteObservation struct {
	read         store.IncidentTestMeasurement
	corroborates bool
}

type incidentRemoteGroup struct {
	failures []incidentRemoteObservation
	healthy  []incidentRemoteObservation
}

func classifyIncidentRemoteResponses(ctx context.Context, input incidentVerdictEvidence, seen map[string]incident.VerdictCitation, remaining *int64, hypothesis *incident.VerdictHypothesis) (bool, *incident.VerdictRemoteProvider, error) {
	groups := map[string]*incidentRemoteGroup{}
	for _, item := range input.tests {
		if err := ctx.Err(); err != nil {
			return false, nil, err
		}
		origin, ok := incidentVerdictHTTPSOrigin(item.source)
		if !ok {
			continue
		}
		key := item.source.ContextID + ":" + origin
		group := groups[key]
		if group == nil {
			group = &incidentRemoteGroup{}
			groups[key] = group
		}
		if err := collectIncidentHTTPResponses(ctx, item, group, input, seen, remaining, hypothesis); err != nil {
			return false, nil, err
		}
	}
	proven := false
	attribution := incidentProviderAttribution{asOf: time.Now().UTC(), ranges: input.serviceRanges}
	providerBudget := *remaining / 16
	for _, group := range groups {
		support := corroboratingHTTPFailures(group.failures, group.healthy)
		proven = proven || len(support) != 0
		for _, observation := range support {
			attribution.observe(ctx, observation.read, &providerBudget)
		}
	}
	if proven {
		hypothesis.Confidence = "corroborated"
	} else {
		hypothesis.Missing = append(hypothesis.Missing, "independent_contemporaneous_same_origin_https_failures")
	}
	return proven, attribution.result(), ctx.Err()
}

func collectIncidentHTTPResponses(ctx context.Context, item incidentVerdictTest, group *incidentRemoteGroup, input incidentVerdictEvidence,
	seen map[string]incident.VerdictCitation, remaining *int64, hypothesis *incident.VerdictHypothesis) error {
	for _, read := range item.reads {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !verdictObservationInWindow(read.ObservedAt, input) {
			continue
		}
		citation := testVerdictCitation(read, "")
		fresh, err := admitVerdictOriginal(citation, seen, remaining)
		if err != nil {
			return err
		}
		if !fresh {
			continue
		}
		outcome := read.Outcome
		if !read.Available || !outcome.VerifiedPrimaryHTTPS() || outcome.StartedAt.Before(input.from) ||
			outcome.StartedAt.Before(item.source.CurrentSince) || outcome.CompletedAt.Before(outcome.StartedAt) || !outcome.CompletedAt.Equal(read.ObservedAt) {
			hypothesis.Missing = append(hypothesis.Missing, "original_verified_primary_https_response")
			continue
		}
		switch status := outcome.HTTPResponse.StatusCode; {
		case status >= 500 && status <= 599 && !outcome.Success:
			citation.Reason = "verified_primary_same_origin_https_server_error"
			hypothesis.For = append(hypothesis.For, citation)
			group.failures = append(group.failures, incidentRemoteObservation{read: read})
		case status >= 200 && status <= 299 && outcome.Success:
			citation.Reason = "verified_primary_same_origin_https_success"
			hypothesis.Against = append(hypothesis.Against, citation)
			group.healthy = append(group.healthy, incidentRemoteObservation{read: read})
		default:
			hypothesis.Missing = append(hypothesis.Missing, "interpretable_primary_https_server_outcome")
		}
	}
	return nil
}

func incidentVerdictHTTPSOrigin(source store.IncidentConfiguredTest) (string, bool) {
	now := time.Now().UTC()
	if source.Type != "http" || source.Definition.Type != "http" || source.Target != source.Definition.Target || source.AgentID == "" ||
		source.MeasurementIdentityUntil == nil || !source.MeasurementIdentityUntil.After(now) || source.ValidUntil != nil && !source.ValidUntil.After(now) {
		return "", false
	}
	u, err := url.Parse(source.Target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" {
		return "", false
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port), true
}

// Retain the latest two uncontradicted failure ends from different agents.
// corroboratingHTTPFailures finds every failure in an independent overlapping
// pair. A healthy overlap disqualifies its probe while earlier healthy periods
// and later recoveries remain citations. Sort and sweep in O(n log n) time.
func corroboratingHTTPFailures(failures, healthy []incidentRemoteObservation) []incidentRemoteObservation {
	byStart := func(a, b incidentRemoteObservation) int {
		return a.read.Outcome.StartedAt.Compare(b.read.Outcome.StartedAt)
	}
	slices.SortFunc(failures, byStart)
	slices.SortFunc(healthy, byStart)
	eligible := failures[:0]
	for _, observation := range failures {
		read := observation.read
		for len(healthy) > 0 && healthy[0].read.Outcome.CompletedAt.Before(read.Outcome.StartedAt) {
			healthy = healthy[1:]
		}
		if len(healthy) > 0 && !healthy[0].read.Outcome.StartedAt.After(read.Outcome.CompletedAt) {
			continue
		}
		eligible = append(eligible, observation)
	}
	type boundary struct {
		agent string
		at    time.Time
	}
	first, second := boundary{}, boundary{}
	for i := range eligible {
		read := eligible[i].read
		other := first
		if other.agent == read.AgentID {
			other = second
		}
		eligible[i].corroborates = other.agent != "" && other.at.After(read.Outcome.StartedAt)
		current := boundary{agent: read.AgentID, at: read.Outcome.CompletedAt}
		switch {
		case current.agent == first.agent:
			if current.at.After(first.at) {
				first = current
			}
		case current.at.After(first.at):
			second, first = first, current
		case current.agent == second.agent:
			if current.at.After(second.at) {
				second = current
			}
		case current.at.After(second.at):
			second = current
		}
	}
	// The reverse sweep finds the first later start from a different agent.
	// A probe that preceded its partner is then retained as provenance too.
	first, second = boundary{}, boundary{}
	for i := len(eligible) - 1; i >= 0; i-- {
		read := eligible[i].read
		other := first
		if other.agent == read.AgentID {
			other = second
		}
		eligible[i].corroborates = eligible[i].corroborates || (other.agent != "" && other.at.Before(read.Outcome.CompletedAt))
		if first.agent != read.AgentID {
			second = first
		}
		first = boundary{agent: read.AgentID, at: read.Outcome.StartedAt}
	}
	return slices.DeleteFunc(eligible, func(observation incidentRemoteObservation) bool {
		return !observation.corroborates
	})
}
