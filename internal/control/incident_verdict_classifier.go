// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var errIncidentVerdictInput = errors.New("incident verdict evidence is invalid")

// These are operation-local server joins, never request fields or authority.
// The caller resolves complete incident membership, current roles and source
// grants in tenant storage and rechecks them at publication. No signal prose,
// raw attribute or model output enters the classifier.
type incidentVerdictInterface struct {
	source store.IncidentInterfaceStateSource
	role   interfaceRoleExplanation
	reads  []store.IncidentInterfaceStateMeasurement
	// Direct membership is derived from the complete incident's canonical
	// root/signal references, not an address or the router's whole inventory.
	direct bool
}

type incidentVerdictTest struct {
	source store.IncidentConfiguredTest
	reads  []store.IncidentTestMeasurement
}

type incidentVerdictEvidence struct {
	tenantID   string
	from, to   time.Time
	interfaces []incidentVerdictInterface
	tests      []incidentVerdictTest
}

// classifyIncidentVerdict currently evaluates original local interface states
// and primary HTTPS responses. Carrier and wider-internet remain explicitly
// unavailable until their own current routing/path readers supply proof. A
// transit label, missing hop, route change or public overlap cannot stand in.
func classifyIncidentVerdict(ctx context.Context, input incidentVerdictEvidence, maxBytes int64) (incident.FaultVerdict, error) {
	none := incident.FaultVerdict{}
	if err := validateIncidentVerdictScope(ctx, input); err != nil {
		return none, err
	}
	if input.from.IsZero() || !input.to.After(input.from) || input.to.After(time.Now().UTC()) {
		return none, errIncidentVerdictInput
	}
	if maxBytes < 4096 || int64(len(input.interfaces))+int64(len(input.tests)) > maxBytes/2048 {
		return none, store.ErrIncidentImpactBudget
	}
	result := incident.FaultVerdict{Domain: incident.FaultUnknown, Confidence: "insufficient",
		Reason: "insufficient_original_evidence", From: input.from, To: input.to,
		Hypotheses: make([]incident.VerdictHypothesis, 4)}
	for i, domain := range []incident.FaultDomain{incident.FaultYourNetwork, incident.FaultCarrier, incident.FaultWiderInternet, incident.FaultRemoteService} {
		result.Hypotheses[i] = incident.VerdictHypothesis{Domain: domain, Confidence: "insufficient",
			For: []incident.VerdictCitation{}, Against: []incident.VerdictCitation{}, Missing: []string{}}
	}
	remaining := maxBytes / 2
	seen := map[string]incident.VerdictCitation{}
	local, err := classifyIncidentLocalInterfaces(ctx, input, seen, &remaining, &result.Hypotheses[0])
	if err != nil {
		return none, err
	}
	remote, err := classifyIncidentRemoteResponses(ctx, input, seen, &remaining, &result.Hypotheses[3])
	if err != nil {
		return none, err
	}
	result.Hypotheses[1].Missing = append(result.Hypotheses[1].Missing, "original_carrier_failure_and_current_asn_handoff")
	result.Hypotheses[2].Missing = append(result.Hypotheses[2].Missing, "independent_current_internet_path_failure")
	switch {
	case local && remote:
		result.Reason = "competing_fault_domains"
	case local:
		result.Domain, result.Confidence, result.Reason = incident.FaultYourNetwork, "direct", "original_unplanned_local_interface_down"
	case remote:
		result.Domain, result.Confidence, result.Reason = incident.FaultRemoteService, "corroborated", "independent_verified_primary_https_server_errors"
	}
	for i := range result.Hypotheses {
		sortVerdictCitations(result.Hypotheses[i].For)
		sortVerdictCitations(result.Hypotheses[i].Against)
		slices.Sort(result.Hypotheses[i].Missing)
		result.Hypotheses[i].Missing = slices.Compact(result.Hypotheses[i].Missing)
	}
	return result, ctx.Err()
}

// Check every scope before interpreting any body. The pure classifier adds a
// defense-in-depth check; actual isolation remains the storage reader's job.
func validateIncidentVerdictScope(ctx context.Context, input incidentVerdictEvidence) error {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || input.tenantID == "" || tenant.String() != input.tenantID {
		return entity.ErrScopeMismatch
	}
	for _, item := range input.interfaces {
		if item.source.TenantID != input.tenantID || item.role.TenantID != input.tenantID ||
			item.role.ContextID != item.source.ContextID || item.role.InterfaceID != item.source.EntityID {
			return entity.ErrScopeMismatch
		}
		for _, read := range item.reads {
			if read.TenantID != input.tenantID || read.ContextID != item.source.ContextID || read.EntityID != item.source.EntityID ||
				read.AgentID != item.source.AgentID || read.ConfiguredRef != item.source.ConfiguredRef || read.IfIndex != item.source.IfIndex || read.SourceGeneration != item.source.SourceGeneration {
				return entity.ErrScopeMismatch
			}
		}
	}
	for _, item := range input.tests {
		if item.source.TenantID != input.tenantID {
			return entity.ErrScopeMismatch
		}
		for _, read := range item.reads {
			if read.TenantID != input.tenantID || read.ContextID != item.source.ContextID || read.EntityID != item.source.EntityID ||
				read.AgentID != item.source.AgentID || read.TestID != item.source.TestID || read.SourceGeneration != item.source.SourceGeneration {
				return entity.ErrScopeMismatch
			}
		}
	}
	return ctx.Err()
}

func chargeVerdictCitation(remaining *int64, citation incident.VerdictCitation) error {
	cost := int64(1024) + 8*int64(len(citation.ContextID)+len(citation.EntityID)+len(citation.EvidenceID)+len(citation.AgentID)+len(citation.Digest)+len(citation.Reason))
	if cost > *remaining {
		return store.ErrIncidentImpactBudget
	}
	*remaining -= cost
	return nil
}

func verdictObservationInWindow(at time.Time, input incidentVerdictEvidence) bool {
	return !at.Before(input.from) && at.Before(input.to)
}

func sortVerdictCitations(items []incident.VerdictCitation) {
	slices.SortFunc(items, func(a, b incident.VerdictCitation) int {
		if c := a.ObservedAt.Compare(b.ObservedAt); c != 0 {
			return c
		}
		if a.EvidenceID < b.EvidenceID {
			return -1
		}
		if a.EvidenceID > b.EvidenceID {
			return 1
		}
		return 0
	})
}

func interfaceVerdictCitation(read store.IncidentInterfaceStateMeasurement, reason string) incident.VerdictCitation {
	return incident.VerdictCitation{ContextID: read.ContextID, EntityID: read.EntityID,
		EvidenceID: read.EvidenceID, AgentID: read.AgentID, ObservedAt: read.ObservedAt,
		Digest: hex.EncodeToString(read.CaptureDigest[:]), Reason: reason}
}

func testVerdictCitation(read store.IncidentTestMeasurement, reason string) incident.VerdictCitation {
	return incident.VerdictCitation{ContextID: read.ContextID, EntityID: read.EntityID,
		EvidenceID: read.EvidenceID, AgentID: read.AgentID, ObservedAt: read.ObservedAt,
		Digest: hex.EncodeToString(read.CaptureDigest[:]), Reason: reason}
}
