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
	"math/big"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func (s *Server) incidentImpact(ctx context.Context, actor *auth.Principal, id string, input incident.ImpactInput) (_ incident.ImpactResponse, operationErr error) {
	finish := s.beginFlowOperation(ctx, "incident_impact")
	defer func() { finish(operationErr) }()
	none := incident.ImpactResponse{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return none, apierror.Validation("canonical incident identity is required")
	}
	if input.From.IsZero() || input.To.IsZero() {
		return none, apierror.Validation("explicit incident comparison from/to are required")
	}
	plan, err := flow.NormalizeQueryPlan(flow.QueryPlan{From: input.From, To: input.To, DataSeries: input.DataSeries}, time.Now().UTC())
	if err != nil {
		return none, apierror.Validation(err.Error())
	}
	previousFrom, previousTo := plan.From.Add(-7*24*time.Hour), plan.To.Add(-7*24*time.Hour)
	// Two flow-result shares and two shared metadata/publication shares use
	// the SAME captured operation envelope. Do not divide the metadata share
	// a second time by the number of comparison queries.
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	budget.MemoryBytes /= 2
	batch, err := flowstore.NewPlanBatch(ctx, s.flowStore, actor.TenantID, 2, 2)
	if err != nil {
		return none, flowExplorerStoreError(err)
	}
	defer batch.Close()
	ctx = batch.Context()
	before, err := s.loadIncidentImpactSnapshot(ctx, actor, id, nil, budget)
	if err != nil {
		return none, err
	}
	sources := []flowstore.IncidentTrafficSource{}
	for _, source := range before.sources {
		sources = append(sources, source.Selections...)
	}
	periods := [2]incident.ImpactPeriod{
		{From: plan.From, To: plan.To, Coverage: "unavailable_source", Captures: []incident.ImpactCaptureCitation{}},
		{From: previousFrom, To: previousTo, Coverage: "unavailable_source", Captures: []incident.ImpactCaptureCitation{}},
	}
	var rows [2][]flowstore.Row
	if len(sources) > 0 {
		for i, period := range periods {
			periods[i].Coverage = "no_observed_records"
			rows[i], err = batch.IncidentTrafficRows(flowstore.IncidentTrafficQuery{TenantID: actor.TenantID, From: period.From, To: period.To, Series: plan.DataSeries, Sources: sources})
			if err != nil {
				return none, flowExplorerStoreError(err)
			}
		}
	}
	reads := []flowstore.RoutingCaptureRead{}
	readsByKey := map[[32]byte]flowstore.RoutingCaptureRead{}
	for _, period := range rows {
		selected, err := flowstore.IncidentTrafficCaptureReferences(ctx, actor.TenantID, period, budget.MemoryBytes/8)
		if err != nil {
			return none, flowExplorerStoreError(err)
		}
		for _, read := range selected {
			if old, found := readsByKey[read.Ref.Key]; found {
				if old != read {
					return none, apierror.Unavailable("original flow capture selectors disagree")
				}
				continue // Comparison windows may legitimately overlap.
			}
			readsByKey[read.Ref.Key] = read
			reads = append(reads, read)
		}
	}
	observed, err := s.loadIncidentImpactSnapshot(ctx, actor, id, reads, budget)
	if err != nil {
		return none, err
	}
	if before.sourceDigest != observed.sourceDigest {
		return none, apierror.Unavailable("incident membership or current source authority changed; retry")
	}
	tagData, err := s.loadIncidentImpactTags(ctx, actor, observed, input.CustomerTagKey)
	if err != nil {
		return none, err
	}
	owners := map[string]store.CapturedFlowOwner{}
	coverage := incidentImpactSourceCoverage(observed.sources)
	for _, owner := range observed.owners {
		owners[hex.EncodeToString(owner.Reference.Key[:])] = owner
	}
	// Interface indices are local identities beneath their original router.
	// Do not assign an older observation to an interface created/rebound later.
	for _, period := range rows {
		for _, row := range period {
			owner, found := owners[row.RoutingCaptureKey]
			if found && owner.Available && !coverage.covers(row, owner) {
				owner.Available = false
				owners[row.RoutingCaptureKey] = owner
			}
		}
	}
	for i := range periods {
		periods[i], err = summarizeIncidentTraffic(ctx, actor.TenantID, periods[i], rows[i], owners, budget.MemoryBytes/8)
		if err != nil {
			return none, err
		}
	}
	result := incident.ImpactResponse{ContractVersion: "probectl.incident-impact.v1", Preview: true,
		IncidentID: id, EvaluatedAt: time.Now().UTC(), Current: periods[0], Previous: periods[1],
		Members: []incident.ImpactMember{}, UnresolvedRoot: before.inputs.RootUnresolved,
		UnresolvedSignalIDs: slices.Clone(before.inputs.UnresolvedSignalIDs), Customers: []incident.ImpactCustomer{}, CustomerCoverage: "not_evaluated",
		Interpretation: "Exact counters for observed, originally attested measurement points; distinct exporters are distinct observations. Missing source/capture coverage is unavailable, not zero. Sampling scales observed counters and does not prove complete telemetry. A weekly traffic decrease does not establish incident-caused loss."}
	for _, source := range observed.sources {
		result.Members = append(result.Members, incident.ImpactMember{ContextID: source.Member.ContextID, EntityID: source.Member.EntityID,
			Kind: string(source.Kind), IncidentRoot: source.Member.IncidentRoot, SignalIDs: slices.Clone(source.Member.SignalIDs), Reason: source.Reason, SourceIDs: slices.Clone(source.Evidence)})
	}
	if tagData != nil {
		result.Customers, result.UnclassifiedRecords, err = summarizeIncidentCustomers(ctx, actor.TenantID, input.CustomerTagKey, rows, owners, tagData, budget.MemoryBytes/8)
		if err != nil {
			return none, flowExplorerStoreError(err)
		}
		result.CustomerTagRevision, err = tagData.Revision(actor.TenantID)
		if err != nil {
			return none, err
		}
		result.CustomerCoverage = "observed_flow_prefixes_only_tests_and_slos_not_evaluated"
	}
	if periods[0].Coverage == "observed_attested_records" && periods[1].Coverage == "observed_attested_records" {
		var current, previous big.Int
		current.SetString(periods[0].ObservedTotals.ScaledBytes, 10)
		previous.SetString(periods[1].ObservedTotals.ScaledBytes, 10)
		result.ObservedByteChange = current.Sub(&current, &previous).String()
	}
	// Refresh current credential, source, assignment and erasure authority for
	// the original retained selectors. This does not execute another flow query.
	after, err := s.loadIncidentImpactSnapshot(ctx, actor, id, reads, budget)
	if err != nil {
		return none, err
	}
	if observed.sourceDigest != after.sourceDigest || observed.captureDigest != after.captureDigest {
		return none, apierror.Unavailable("current incident or original capture authority changed; retry")
	}
	if tagData != nil {
		currentTags, err := s.loadIncidentImpactTags(ctx, actor, after, input.CustomerTagKey)
		if err != nil {
			return none, err
		}
		currentCustomers, unclassified, err := summarizeIncidentCustomers(ctx, actor.TenantID, input.CustomerTagKey, rows, owners, currentTags, budget.MemoryBytes/8)
		if err != nil {
			return none, flowExplorerStoreError(err)
		}
		revision, err := currentTags.Revision(actor.TenantID)
		if err != nil {
			return none, err
		}
		originalPolicy, err := tagData.ContextAuthorization(actor.TenantID)
		if err != nil {
			return none, err
		}
		currentPolicy, err := currentTags.ContextAuthorization(actor.TenantID)
		if err != nil {
			return none, err
		}
		oldBody, err := json.Marshal(result.Customers)
		if err != nil {
			return none, err
		}
		newBody, err := json.Marshal(currentCustomers)
		if err != nil {
			return none, err
		}
		if revision != result.CustomerTagRevision || originalPolicy != currentPolicy || unclassified != result.UnclassifiedRecords || string(oldBody) != string(newBody) {
			return none, apierror.Unavailable("customer prefix membership or disclosure authority changed; retry")
		}
	}
	for _, source := range after.sources {
		if !source.ValidUntil.IsZero() && !source.ValidUntil.After(time.Now().UTC()) {
			return none, apierror.Unavailable("incident source evidence expired; retry")
		}
		if !source.ValidUntil.IsZero() && (result.ValidUntil == nil || source.ValidUntil.Before(*result.ValidUntil)) {
			until := source.ValidUntil
			result.ValidUntil = &until
		}
	}
	body, err := json.Marshal(result)
	if err != nil {
		return none, err
	}
	if int64(len(body)) > budget.ResponseBytes {
		return none, flowExplorerStoreError(flowstore.ErrExplorerBudget)
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return result, nil
}

type incidentTrafficCounters struct{ rawBytes, rawPackets, scaledBytes, scaledPackets big.Int }

func (totals *incidentTrafficCounters) add(row flowstore.Row) {
	var value, scale big.Int
	scale.SetUint64(row.Sampling)
	value.SetUint64(row.Bytes)
	totals.rawBytes.Add(&totals.rawBytes, &value)
	value.Mul(&value, &scale)
	totals.scaledBytes.Add(&totals.scaledBytes, &value)
	value.SetUint64(row.Packets)
	totals.rawPackets.Add(&totals.rawPackets, &value)
	value.Mul(&value, &scale)
	totals.scaledPackets.Add(&totals.scaledPackets, &value)
}

func (totals *incidentTrafficCounters) response() *incident.ImpactCounters {
	return &incident.ImpactCounters{RawBytes: totals.rawBytes.String(), RawPackets: totals.rawPackets.String(), ScaledBytes: totals.scaledBytes.String(), ScaledPackets: totals.scaledPackets.String()}
}

func summarizeIncidentTraffic(ctx context.Context, tenant string, period incident.ImpactPeriod, rows []flowstore.Row, owners map[string]store.CapturedFlowOwner, maxBytes int64) (incident.ImpactPeriod, error) {
	none := incident.ImpactPeriod{}
	seen := map[string]bool{}
	var totals incidentTrafficCounters
	remaining := maxBytes
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if row.TenantID != tenant || row.TS.Before(period.From) || !row.TS.Before(period.To) {
			return none, flowExplorerStoreError(flowstore.ErrNoTenant)
		}
		owner, found := owners[row.RoutingCaptureKey]
		if !found || !incidentTrafficOwnerMatches(row, owner) {
			period.UnverifiedRecords++
			continue
		}
		if seen[row.RoutingCaptureKey] {
			continue
		}
		cost := int64(2048 + len(row.RoutingCaptureKey) + len(owner.Owner.SourceID) + len(owner.CurrentSourceID))
		if row.Sampling == 0 || cost > remaining {
			return none, flowExplorerStoreError(flowstore.ErrExplorerBudget)
		}
		remaining -= cost
		seen[row.RoutingCaptureKey] = true
		period.AttestedRecords++
		totals.add(row)
		period.Captures = append(period.Captures, incident.ImpactCaptureCitation{Key: row.RoutingCaptureKey, CapturedAt: owner.Reference.CapturedAt,
			ContextID: owner.Owner.ContextID, RouterID: owner.Owner.RouterID, OriginalSourceID: owner.Owner.SourceID, CurrentSourceID: owner.CurrentSourceID})
	}
	slices.SortFunc(period.Captures, func(a, b incident.ImpactCaptureCitation) int {
		return slices.Compare([]string{a.Key}, []string{b.Key})
	})
	if period.AttestedRecords > 0 {
		period.ObservedTotals = totals.response()
		period.Coverage = "observed_attested_records"
		if period.UnverifiedRecords > 0 {
			period.Coverage = "partial_capture_coverage"
		}
	} else if len(rows) > 0 {
		period.Coverage = "unavailable_original_capture"
	} else if period.Coverage != "unavailable_source" {
		period.Coverage = "no_observed_records"
	}
	return period, nil
}

func incidentTrafficOwnerMatches(row flowstore.Row, owner store.CapturedFlowOwner) bool {
	return row.RoutingCaptureKey != "" && owner.Available && owner.Owner.TenantID == row.TenantID &&
		!row.TS.Before(owner.CurrentOwnerSince) && (row.StartTS.IsZero() || !row.StartTS.Before(owner.CurrentOwnerSince)) &&
		owner.Owner.AgentID == row.AgentID && owner.Owner.Exporter.String() == row.Exporter && owner.Owner.Protocol == row.Protocol && owner.Owner.Domain == row.ObsDomain &&
		hex.EncodeToString(owner.Reference.Key[:]) == row.RoutingCaptureKey && owner.Reference.CapturedAt.UnixNano() == row.RoutingCapturedUnixNanos
}
