// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/store/pathstore"
)

type incidentVerdictPathBinding struct {
	TestID  string
	Binding store.PathTestBinding
}

type incidentVerdictPathGroup struct {
	Target string
	Rounds []pathstore.Snapshot
}

type incidentVerdictPath struct {
	source  store.IncidentConfiguredTest
	binding store.PathTestBinding
	since   time.Time
	rounds  []pathstore.Snapshot
}

func (s *Server) loadIncidentVerdictPaths(ctx context.Context, snapshot, original *incidentVerdictSnapshot, memory *int64) error {
	if s.pathStore == nil {
		return nil
	}
	groups := map[string][]pathstore.Snapshot{}
	originals := map[string][]pathstore.Snapshot{}
	if original != nil {
		for _, group := range original.pathGroups {
			originals[group.Target] = group.Rounds
		}
	}
	merged := map[string]int{}
	remaining := *memory
	for _, source := range snapshot.tests {
		if source.PathBinding == nil {
			snapshot.pathBindings = append(snapshot.pathBindings, incidentVerdictPathBinding{TestID: source.TestID})
			continue
		}
		binding := *source.PathBinding
		if binding.Scope.TenantID != source.TenantID || binding.Scope.ContextID != source.ContextID || binding.Target != path.TargetHost(source.Target) {
			return entity.ErrScopeMismatch
		}
		snapshot.pathBindings = append(snapshot.pathBindings, incidentVerdictPathBinding{source.TestID, binding})
		rounds, found := groups[binding.Target]
		if !found {
			var err error
			query := pathstore.HistoryQuery{From: snapshot.evidence.from, To: snapshot.evidence.to.Add(-time.Nanosecond), MaxBytes: remaining / 2}
			if original != nil {
				before, found := originals[binding.Target]
				if !found {
					return apierror.Unavailable("incident path binding changed; retry")
				}
				for _, round := range before {
					query.IDs = append(query.IDs, round.ID)
				}
				if len(before) == 0 {
					rounds = []pathstore.Snapshot{} // Do not substitute a new history.
				}
			}
			if rounds == nil {
				rounds, err = s.pathStore.History(ctx, source.TenantID, binding.Target, query)
				if errors.Is(err, pathstore.ErrHistoryBudget) || errors.Is(err, chclient.ErrResponseTooLarge) {
					return apierror.Unavailable("complete incident path history exceeds configured query memory; increase the query memory allowance")
				}
				if err != nil {
					return err
				}
			}
			if original != nil && len(rounds) != len(originals[binding.Target]) {
				return apierror.Unavailable("original incident path rounds are no longer complete; retry")
			}
			body, err := json.Marshal(rounds)
			if err != nil {
				return err
			}
			cost := int64(4096) + 8*int64(len(body))
			if cost > remaining {
				return store.ErrIncidentImpactBudget
			}
			remaining -= cost
			groups[binding.Target] = rounds
			snapshot.pathGroups = append(snapshot.pathGroups, incidentVerdictPathGroup{binding.Target, rounds})
		}
		since := binding.AssignedAt
		if source.CurrentSince.After(since) {
			since = source.CurrentSince
		}
		key := source.ContextID + ":" + source.EntityID + ":" + binding.Target
		if index, found := merged[key]; found {
			if since.Before(snapshot.evidence.paths[index].since) {
				snapshot.evidence.paths[index].since = since
			}
			continue
		}
		merged[key] = len(snapshot.evidence.paths)
		snapshot.evidence.paths = append(snapshot.evidence.paths, incidentVerdictPath{source, binding, since, rounds})
	}
	*memory = remaining
	return ctx.Err()
}

// A control-plane trace is never an agent vantage or a localized carrier
// failure. A measured terminal reply supplies limited contrary evidence;
// absent hops supply missing coverage, never proof of a failed AS.
func classifyIncidentControlPlanePaths(ctx context.Context, input incidentVerdictEvidence, seen map[string]incident.VerdictCitation, remaining *int64, hypotheses []incident.VerdictHypothesis) error {
	for _, selected := range input.paths {
		for _, round := range selected.rounds {
			if !verdictObservationInWindow(round.ObservedAt, input) || !round.TrustedDiscoveryTime || !round.ObservedAt.After(selected.since) || round.Path.Target != selected.binding.Target {
				continue
			}
			if round.CompletedAt == nil || round.CompletedAt.Before(round.ObservedAt) || !verdictObservationInWindow(*round.CompletedAt, input) {
				hypotheses[1].Missing = append(hypotheses[1].Missing, "complete_original_path_execution_interval_in_window")
				hypotheses[2].Missing = append(hypotheses[2].Missing, "complete_original_path_execution_interval_in_window")
				continue
			}
			if !verdictPathHasTerminalReply(round.Path) {
				hypotheses[1].Missing = append(hypotheses[1].Missing, "control_plane_missing_hops_do_not_localize_carrier_failure")
				hypotheses[2].Missing = append(hypotheses[2].Missing, "control_plane_missing_hops_do_not_prove_internet_failure")
				continue
			}
			digest, err := hashFlowRoleInputs(ctx, nil, round, *remaining)
			if err != nil {
				return err
			}
			citation := incident.VerdictCitation{ContextID: selected.source.ContextID, EntityID: selected.source.EntityID, SourceKind: "control_plane_path", PathRoundID: round.ID, AgentID: path.VantageControlPlane,
				Digest: hex.EncodeToString(digest), ObservedAt: *round.CompletedAt, Reason: "control_plane_terminal_reply_not_an_agent_path"}
			fresh, err := admitVerdictOriginal(citation, seen, remaining)
			if err != nil {
				return err
			}
			if fresh {
				hypotheses[1].Against = append(hypotheses[1].Against, citation)
				hypotheses[2].Against = append(hypotheses[2].Against, citation)
			}
		}
	}
	return ctx.Err()
}

func verdictPathHasTerminalReply(p path.Path) bool {
	f := p.MeasurementFidelity
	if f == nil || f.Version != 1 || f.TimingSource != "application_monotonic" || p.TargetIP == "" || p.Vantage != "" && p.Vantage != path.VantageControlPlane {
		return false
	}
	if f.HopVisibility != "full" && f.HopVisibility != "destination_only" && f.HopVisibility != "mixed" {
		return false
	}
	switch f.ProbeTransport {
	case "icmp":
		if p.Mode != "icmp" || f.AcquisitionMode != "raw_icmp" && f.AcquisitionMode != "icmp_datagram" && f.AcquisitionMode != "mixed" {
			return false
		}
	case "tcp":
		if p.Mode != "tcp" || f.AcquisitionMode != "tcp_connect_raw_icmp" && f.AcquisitionMode != "tcp_connect" && f.AcquisitionMode != "mixed" {
			return false
		}
	case "mixed":
		if f.AcquisitionMode != "mixed" || p.Mode != "icmp" && p.Mode != "tcp" {
			return false
		}
	default:
		return false
	}
	for _, hop := range p.Hops {
		for _, node := range hop.Nodes {
			if node.IP == p.TargetIP && node.Received > 0 && node.Sent >= node.Received {
				return true
			}
		}
	}
	return false
}
