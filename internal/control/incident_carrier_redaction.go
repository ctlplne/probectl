// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"slices"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
)

func redactIncidentCarrier(value incident.CarrierPack, pol ai.RedactionPolicy, tenant string) (incident.CarrierPack, error) {
	pol = incidentEvidenceTenantPolicy(pol, tenant)
	body, err := json.Marshal(value)
	if err != nil {
		return incident.CarrierPack{}, err
	}
	var out incident.CarrierPack
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	out.AddressesRedacted = pol.MaskIPs
	// Canonical citation identities, hashes and exact decimal measurements stay
	// typed. Only untrusted text and selected path addresses enter the redactor.
	for i := range out.Vantages {
		vantage := &out.Vantages[i]
		vantage.AgentID = ai.RedactTextForTenant(vantage.AgentID, pol, tenant)
		for j := range vantage.Measurements.Observations {
			observation := &vantage.Measurements.Observations[j]
			observation.Reason = ai.RedactTextForTenant(observation.Reason, pol, tenant)
		}
		for j := range vantage.Traces {
			trace := &vantage.Traces[j]
			redacted, err := redactCarrierPath(trace.Path, pol, tenant)
			if err != nil {
				return incident.CarrierPack{}, err
			}
			trace.Path = redacted
		}
	}
	for i := range out.Routing {
		event := &out.Routing[i]
		event.TenantID = ""
		event.Title = ""
		event.Summary = ""
		event.Actor = ""
		event.URL = ""
		event.Attributes = nil
		event.Prefix = ai.RedactTextForTenant(event.Prefix, pol, tenant)
	}
	for i := range out.Handoffs {
		handoff := &out.Handoffs[i]
		handoff.AgentID = ai.RedactTextForTenant(handoff.AgentID, pol, tenant)
		handoff.SourceRef = ai.RedactTextForTenant(handoff.SourceRef, pol, tenant)
	}
	return out, nil
}

func redactCarrierPath(original path.Path, pol ai.RedactionPolicy, tenant string) (path.Path, error) {
	var out path.Path
	original.Hops = slices.Clone(original.Hops)
	for hop := range original.Hops {
		original.Hops[hop].Nodes = slices.Clone(original.Hops[hop].Nodes)
		for node := range original.Hops[hop].Nodes {
			original.Hops[hop].Nodes[node].Geo = nil
		}
	}
	raw, err := json.Marshal(original)
	if err != nil {
		return out, err
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return out, err
	}
	redacted, err := json.Marshal(redactShareAnswerValue("", fields, pol, tenant))
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(redacted, &out)
	return out, err
}
