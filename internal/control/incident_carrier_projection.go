// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testspec"
)

// This projection has no authority of its own. The caller retains the complete
// tenant snapshot and rechecks its exact sources before signed publication.
func projectIncidentCarrier(ctx context.Context, tenant, id string, from, to time.Time, snapshot incidentVerdictSnapshot, memory int64) (incident.CarrierPack, error) {
	none := incident.CarrierPack{}
	if snapshot.inputs == nil || snapshot.inputs.TenantID != tenant || snapshot.inputs.IncidentID != id || snapshot.evidence.tenantID != tenant || !snapshot.evidence.from.Equal(from) || !snapshot.evidence.to.Equal(to) {
		return none, entity.ErrScopeMismatch
	}
	periods, err := summarizeOriginalTestPeriods(ctx, tenant, snapshot.tests, snapshot.outcomes, []originalMeasurementWindow{{from, to}}, memory/2)
	if err != nil {
		return none, err
	}
	out := incident.CarrierPack{ContractVersion: incident.CarrierContractVersion, IncidentID: id, GeneratedAt: time.Now().UTC(), From: from, To: to,
		Interpretation: "Original measurements in the selected window under current source grants. Temporal association does not prove carrier fault. Missing measurements are unknown, not successful replies. Current membership is not historical topology.",
		Coverage:       incident.CarrierCoverage{Measurements: "no_retained_observations", Traces: "unavailable", Routing: "unavailable", Handoffs: "unavailable", Missing: []string{}}, Vantages: []incident.CarrierVantage{}, Routing: []change.Event{}, Handoffs: []incident.CarrierHandoff{}}
	remaining := memory / 2
	for _, test := range periods {
		digest, err := testspec.DefinitionHash(test.source.Definition)
		if err != nil {
			return none, err
		}
		vantage := incident.CarrierVantage{ContextID: test.source.ContextID, EntityID: test.source.EntityID, TestID: test.source.TestID, AgentID: test.source.AgentID, DefinitionDigest: digest, Measurements: test.periods[0], Traces: []incident.CarrierTrace{}}
		if len(vantage.Measurements.Observations) > 0 {
			out.Coverage.Measurements = "retained_originals_with_explicit_gaps"
		}
		if binding := test.source.PathBinding; binding != nil {
			if binding.Scope.TenantID != tenant || binding.Scope.ContextID != test.source.ContextID || binding.Target != path.TargetHost(test.source.Target) {
				return none, entity.ErrScopeMismatch
			}
			since := binding.AssignedAt
			if test.source.CurrentSince.After(since) {
				since = test.source.CurrentSince
			}
			for _, group := range snapshot.pathGroups {
				if group.Target != binding.Target {
					continue
				}
				for _, round := range group.Rounds {
					if err := ctx.Err(); err != nil {
						return none, err
					}
					if !round.TrustedDiscoveryTime || !round.ObservedAt.After(since) || round.ObservedAt.Before(from) || !round.ObservedAt.Before(to) || round.Path.Target != binding.Target {
						continue
					}
					if round.Path.Vantage != "" && round.Path.Vantage != path.VantageControlPlane {
						return none, entity.ErrInvalidClaim
					}
					// Retained paths currently originate at the control plane. An empty
					// legacy vantage retains that known origin, never an agent identity.
					original := round.Path
					original.Vantage = path.VantageControlPlane
					size, err := carrierRetainedCost(original)
					if err != nil {
						return none, err
					}
					if size > remaining {
						return none, store.ErrIncidentImpactBudget
					}
					remaining -= size
					coverage := "unavailable_original_completion"
					if round.CompletedAt != nil {
						coverage = "execution_straddles_selected_window"
						if !round.CompletedAt.Before(round.ObservedAt) && round.CompletedAt.Before(to) {
							coverage = "complete_original_interval_in_window"
						}
					}
					vantage.Traces = append(vantage.Traces, incident.CarrierTrace{WindowCoverage: coverage, RoundID: round.ID, ObservedAt: round.ObservedAt, CompletedAt: round.CompletedAt, TrustedDiscoveryTime: true, Vantage: path.VantageControlPlane, Path: original})
					out.Coverage.Traces = "control_plane_only"
				}
			}
		}
		out.Vantages = append(out.Vantages, vantage)
	}
	if snapshot.inputs.RootUnresolved || len(snapshot.inputs.UnresolvedSignalIDs) > 0 {
		out.Coverage.Missing = append(out.Coverage.Missing, "complete_canonical_incident_membership")
	}
	out.Coverage.Missing = append(out.Coverage.Missing, "independent_agent_traceroutes")
	out.Summary = carrierSummary(out)
	return out, ctx.Err()
}

func carrierSummary(value incident.CarrierPack) string {
	observed, unknown := 0, 0
	for _, vantage := range value.Vantages {
		observed += vantage.Measurements.CompleteExecutions
		unknown += vantage.Measurements.UnavailableExecutions
	}
	return fmt.Sprintf("Selected %s to %s: %d configured probe sources, %d complete packet executions and %d unavailable executions; %d original routing changes and %d handoff interfaces. Trace coverage: %s. Source gaps and original observations are included; these observations do not establish causation.", value.From.Format(time.RFC3339Nano), value.To.Format(time.RFC3339Nano), len(value.Vantages), observed, unknown, len(value.Routing), len(value.Handoffs), value.Coverage.Traces)
}

func carrierRetainedCost(value any) (int64, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return 0, err
	}
	return 4096 + 8*int64(len(body)), nil
}
