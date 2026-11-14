// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package evidence

import (
	"encoding/json"
	"errors"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/incident"
)

// The authenticated reader has already selected and redacted complete original
// sources. One content-addressed attachment preserves the whole selection;
// these structural checks do not grant online tenant or source authority.
func carrierEvidence(incidentID string, value incident.CarrierPack) (Record, Attachment, error) {
	if value.ContractVersion != incident.CarrierContractVersion || value.IncidentID != incidentID || value.GeneratedAt.IsZero() || value.From.IsZero() || !value.To.After(value.From) || value.Summary == "" || value.Interpretation == "" ||
		value.Coverage.Measurements == "" || value.Coverage.Traces == "" || value.Coverage.Routing == "" || value.Coverage.Handoffs == "" {
		return Record{}, Attachment{}, errors.New("evidence: carrier identity, window and explicit coverage are required")
	}
	state := StateUnknown
	for _, vantage := range value.Vantages {
		if vantage.ContextID == "" || vantage.EntityID == "" || vantage.TestID == "" || !vantage.Measurements.From.Equal(value.From) || !vantage.Measurements.To.Equal(value.To) {
			return Record{}, Attachment{}, errors.New("evidence: carrier vantage changed its canonical scope or window")
		}
		for _, observation := range vantage.Measurements.Observations {
			if observation.Available {
				state = StateObserved
			}
		}
		for _, trace := range vantage.Traces {
			if trace.RoundID == "" || trace.Vantage == "" || trace.Path.Vantage != trace.Vantage {
				return Record{}, Attachment{}, errors.New("evidence: carrier trace requires its actual original vantage")
			}
			if trace.WindowCoverage == "complete_original_interval_in_window" && trace.TrustedDiscoveryTime && trace.CompletedAt != nil && !trace.ObservedAt.Before(value.From) && trace.ObservedAt.Before(value.To) && !trace.CompletedAt.Before(trace.ObservedAt) && trace.CompletedAt.Before(value.To) {
				state = StateObserved
			}
		}
	}
	for _, route := range value.Routing {
		if route.TenantID != "" || route.Config != nil || route.Kind != change.KindRoute || route.Routing == nil || route.Routing.Validate() != nil {
			return Record{}, Attachment{}, errors.New("evidence: carrier routing requires tenant-redacted original routing references")
		}
		state = StateObserved
	}
	for _, handoff := range value.Handoffs {
		if len(handoff.Counters) > 0 {
			state = StateObserved
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return Record{}, Attachment{}, err
	}
	address := digest(raw)
	return Record{ID: "evidence:" + address, Kind: "incident.carrier", Summary: "Selected original carrier-ticket measurements and source coverage; temporal association is not proof of causation.", State: state, AttachmentDigest: address,
			Provenance: Provenance{Source: "probectl carrier ticket", VantageID: "original source vantages", VantageOwner: "operator-controlled", TrustTier: "authenticated-input-derived", Independence: "see each original source vantage", CapturedAt: value.GeneratedAt,
				Freshness: "as of exported evaluation", ClockQuality: "see original observation clocks", MissingIntervals: []MissingInterval{}}},
		Attachment{Digest: address, MediaType: "application/json", Content: raw}, nil
}
