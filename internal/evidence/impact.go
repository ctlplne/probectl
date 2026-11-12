// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package evidence

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
)

// Impact is recomputed and redacted by the authenticated service. Keeping it
// as one complete content-addressed attachment preserves every member, capture
// and customer citation without a second display/page limit. Its signature
// attests the exported observation; it adds no causal or completeness claim.
func impactEvidence(incidentID string, impact incident.ImpactResponse) (Record, Attachment, error) {
	if impact.ContractVersion != "probectl.incident-impact.v1" || impact.IncidentID != incidentID || impact.EvaluatedAt.IsZero() ||
		!impact.Current.To.After(impact.Current.From) || !impact.Previous.From.Equal(impact.Current.From.Add(-7*24*time.Hour)) || !impact.Previous.To.Equal(impact.Current.To.Add(-7*24*time.Hour)) {
		return Record{}, Attachment{}, errors.New("evidence: impact identity, evaluation and comparison windows must match")
	}
	raw, err := json.Marshal(impact)
	if err != nil {
		return Record{}, Attachment{}, err
	}
	address := digest(raw)
	state := StateUnknown
	if impact.Current.ObservedTotals != nil || impact.Previous.ObservedTotals != nil {
		state = StateObserved
	}
	gaps := []MissingInterval{}
	for _, period := range []incident.ImpactPeriod{impact.Current, impact.Previous} {
		if period.Coverage != "observed_attested_records" {
			gaps = append(gaps, MissingInterval{From: period.From, To: period.To, Reason: period.Coverage})
		}
	}
	return Record{ID: "evidence:" + address, Kind: "incident.impact", Summary: "Observed incident traffic and customer impact, with explicit source coverage and comparison windows.", State: state, AttachmentDigest: address,
			Provenance: Provenance{Source: "probectl incident impact", VantageID: "cited measurement points", VantageOwner: "operator-controlled", TrustTier: "authenticated-input-derived", Independence: "shared cited inputs", CapturedAt: impact.EvaluatedAt,
				Freshness: "as of exported evaluation", ClockQuality: "unknown", MissingIntervals: gaps}},
		Attachment{Digest: address, MediaType: "application/json", Content: raw}, nil
}
