// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package evidence

import (
	"encoding/json"
	"errors"

	"github.com/ctlplne/probectl/internal/incident"
)

// A verdict is derived evidence, not independent measurement or a new grant.
// Preserve the complete already-redacted server result as one attachment;
// offline verification attests these bytes, never an external carrier's truth.
func verdictEvidence(incidentID string, verdict incident.FaultVerdict) (Record, Attachment, error) {
	if err := validateVerdictEvidence(incidentID, verdict); err != nil {
		return Record{}, Attachment{}, err
	}
	raw, err := json.Marshal(verdict)
	if err != nil {
		return Record{}, Attachment{}, err
	}
	address := digest(raw)
	state := StateUnknown
	for _, hypothesis := range verdict.Hypotheses {
		if len(hypothesis.For) != 0 || len(hypothesis.Against) != 0 {
			state = StateObserved
		}
	}
	return Record{ID: "evidence:" + address, Kind: "incident.fault_domain", Summary: "Deterministic fault-domain inference with original supporting/contradicting citations and explicit missing coverage.", State: state, AttachmentDigest: address,
			Provenance: Provenance{Source: "probectl incident fault domain", VantageID: "cited original observations", VantageOwner: "operator-controlled", TrustTier: "authenticated-input-derived", Independence: "shared cited inputs", CapturedAt: verdict.EvaluatedAt, Freshness: "as of exported evaluation; retained authority deadline is not extended", ClockQuality: "unknown", MissingIntervals: []MissingInterval{}}},
		Attachment{Digest: address, MediaType: "application/json", Content: raw}, nil
}

func validateVerdictEvidence(incidentID string, verdict incident.FaultVerdict) error {
	invalid := errors.New("evidence: verdict identity, window and complete hypotheses must match")
	if verdict.ContractVersion != "probectl.incident-verdict.v1" || verdict.IncidentID != incidentID || verdict.EvaluatedAt.IsZero() || verdict.From.IsZero() || !verdict.To.After(verdict.From) || len(verdict.Hypotheses) != 4 {
		return invalid
	}
	if verdict.Confidence != "insufficient" && verdict.Confidence != "corroborated" && verdict.Confidence != "direct" {
		return invalid
	}
	if verdict.Domain == incident.FaultUnknown && verdict.Confidence != "insufficient" {
		return invalid
	}
	if verdict.ValidUntil != nil && !verdict.ValidUntil.After(verdict.EvaluatedAt) {
		return invalid
	}
	wanted := map[incident.FaultDomain]bool{incident.FaultYourNetwork: true, incident.FaultCarrier: true, incident.FaultWiderInternet: true, incident.FaultRemoteService: true}
	selected := verdict.Domain == incident.FaultUnknown
	for _, hypothesis := range verdict.Hypotheses {
		if !wanted[hypothesis.Domain] {
			return invalid
		}
		delete(wanted, hypothesis.Domain)
		if hypothesis.Confidence != "insufficient" && hypothesis.Confidence != "corroborated" && hypothesis.Confidence != "direct" {
			return invalid
		}
		if hypothesis.Domain == verdict.Domain {
			if hypothesis.Confidence != verdict.Confidence || hypothesis.Confidence == "insufficient" || len(hypothesis.For) == 0 {
				return invalid
			}
			selected = true
		}
		for _, citations := range [][]incident.VerdictCitation{hypothesis.For, hypothesis.Against} {
			for _, citation := range citations {
				if citation.ContextID == "" || citation.EntityID == "" || citation.EvidenceID == "" || citation.AgentID == "" || citation.Digest == "" || citation.ObservedAt.Before(verdict.From) || !citation.ObservedAt.Before(verdict.To) {
					return invalid
				}
			}
		}
	}
	if !selected {
		return invalid
	}
	return nil
}
