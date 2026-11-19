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
	"net/http"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type flowFieldComparisonSettings struct {
	View reportFlowSourceRef
	flow.FieldComparisonInput
}

func (s *Server) handleFlowFieldComparison(w http.ResponseWriter, r *http.Request) error {
	actor, err := s.flowViewPrincipal(r, false)
	if err != nil {
		return err
	}
	release, err := s.beginQuery(w, r)
	if err != nil {
		return err
	}
	defer release()
	var input flow.FieldComparisonInput
	if err := decodeJSONLimit(r, 4096, &input); err != nil {
		return err
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(actor.TenantID))
	settings := fieldComparisonSettings(r.PathValue("id"), input)
	result, err := s.readFlowFieldComparison(ctx, actor, settings, time.Now(), nil)
	if err != nil {
		return err
	}
	if err := s.pathAlertRequestCredential(r, actor)(ctx); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

func fieldComparisonSettings(id string, input flow.FieldComparisonInput) flowFieldComparisonSettings {
	input = input.WithDefaults()
	return flowFieldComparisonSettings{View: reportFlowSourceRef{ID: id, Version: input.Version}, FieldComparisonInput: input}
}

func (s flowFieldComparisonSettings) validatePlan(plan flow.QueryPlan) error {
	if plan.View != "table" || len(plan.GroupBy) == 0 || plan.Cursor != "" {
		return apierror.Validation("field comparison needs a saved grouped table view")
	}
	period := time.Duration(s.PeriodSeconds) * time.Second
	if s.Cadence == string(anomaly.FlowFieldCompleteWeek) {
		period = 7 * 24 * time.Hour
	}
	if plan.To.Sub(plan.From) != period {
		return apierror.Validation("saved query lookback must match the field comparison window")
	}
	metrics := map[string]string{}
	for _, metric := range plan.Metrics {
		metrics[metric.Measure+":"+metric.Calculation] = metric.Role
	}
	if metrics[s.Measure] != "primary" {
		return apierror.Validation("field comparison measure must be the saved query's primary metric")
	}
	for _, threshold := range s.SecondaryThresholds {
		if metrics[threshold.Measure] != "secondary" {
			return apierror.Validation("field comparison threshold must refer to a saved secondary metric")
		}
	}
	if s.Mode == "fanout" && (s.Measure != "unique_dst:total" || !slices.Contains(plan.GroupBy, "src_addr")) {
		return apierror.Validation("fan-out comparison groups by source address and measures distinct destinations")
	}
	if s.Mode == "share" && !anomaly.FlowFieldAdditiveMeasure(s.Measure) {
		return apierror.Validation("share comparison requires an additive primary metric")
	}
	return nil
}

// Both periods are original results of one authorized saved source capture.
// The caller retains the same operation admission through publication.
func compareCapturedFlowFields(ctx context.Context, capture *reportFlowCapture, settings flowFieldComparisonSettings, work int64) (flow.FieldComparison, error) {
	var out flow.FieldComparison
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || capture == nil || tenant.String() != capture.TenantID {
		return out, tenancy.ErrNoTenant
	}
	if len(capture.Results) != 2 || len(capture.Inputs) != 2 || capture.SourceGeneration < 1 {
		return out, anomaly.ErrFlowFieldCoverage
	}
	left, right := capture.Results[0], capture.Results[1]
	if left.TenantID != capture.TenantID || right.TenantID != capture.TenantID {
		return out, tenancy.ErrNoTenant
	}
	if left.Result.TagRevision != right.Result.TagRevision || !left.TagAsOf.Equal(right.TagAsOf) ||
		left.Result.RoleDigest != right.Result.RoleDigest {
		return out, anomaly.ErrFlowFieldCoverage
	}
	scope, err := flowFieldAuthorityDigest(capture, settings, right)
	if err != nil {
		return out, err
	}
	before, err := projectRankedFlowField(ctx, left, settings.View, scope, settings.Measure, settings.TopKeys, work/4)
	if err != nil {
		return out, err
	}
	after, err := projectRankedFlowField(ctx, right, settings.View, scope, settings.Measure, settings.TopKeys, work/4)
	if err != nil {
		return out, err
	}
	out = flow.FieldComparison{ViewID: settings.View.ID, Version: settings.View.Version, Mode: settings.Mode, Measure: settings.Measure,
		Cadence: settings.Cadence, TopKeys: settings.TopKeys, Before: flowFieldSlice(left.Result), After: flowFieldSlice(right.Result), Changes: []flow.FieldChange{}}
	switch settings.Mode {
	case "rank":
		thresholds := make([]anomaly.FlowFieldSecondaryThreshold, 0, len(settings.SecondaryThresholds))
		for _, threshold := range settings.SecondaryThresholds {
			thresholds = append(thresholds, anomaly.FlowFieldSecondaryThreshold{Measure: threshold.Measure, Minimum: threshold.Minimum})
		}
		var changes []anomaly.FlowFieldRankChange
		changes, err = anomaly.CompareFlowFieldRanks(ctx, capture.TenantID, before.Ranking, after.Ranking, settings.TopKeys,
			settings.MinimumRankChange, settings.MinimumChange, work/2, thresholds...)
		for _, change := range changes {
			out.Changes = append(out.Changes, flowFieldChange(change.Kind, change.Before, change.After))
		}
	case "amount":
		var changes []anomaly.FlowFieldAmountChange
		changes, err = anomaly.CompareFlowFieldAmounts(ctx, capture.TenantID, before.Ranking, after.Ranking, settings.TopKeys, settings.MinimumChange, work/2)
		for _, change := range changes {
			receipt := flowFieldChange("amount_shift", &change.Before, &change.After)
			receipt.Delta = change.Delta
			out.Changes = append(out.Changes, receipt)
		}
	case "share":
		var changes []anomaly.FlowFieldShareChange
		changes, err = anomaly.CompareFlowFieldShares(ctx, capture.TenantID, before, after, settings.TopKeys, settings.ShareBasisPoints, work/2)
		out.Before.PopulationTotal, out.After.PopulationTotal = before.ParentTotal, after.ParentTotal
		for _, change := range changes {
			receipt := flowFieldChange("share_shift", &change.Before, &change.After)
			receipt.Before.Share, receipt.After.Share = change.BeforeShare, change.AfterShare
			out.Changes = append(out.Changes, receipt)
		}
	case "fanout":
		var changes []anomaly.FlowFanoutChange
		changes, err = anomaly.CompareFlowFanout(ctx, capture.TenantID, before.Ranking, after.Ranking, settings.TopKeys, settings.MinimumChange, work/2)
		for _, change := range changes {
			out.Changes = append(out.Changes, flowFieldChange("fanout_increase", &change.Before, &change.After))
		}
	default:
		err = anomaly.ErrFlowFieldCoverage
	}
	if err != nil {
		return flow.FieldComparison{}, err
	}
	return out, ctx.Err()
}

func flowFieldSlice(result flowstore.PlanResult) flow.FieldComparisonSlice {
	return flow.FieldComparisonSlice{From: result.Query.From, To: result.Query.To, Source: result.Source,
		ResolutionSeconds: result.ResolutionSeconds, TotalGroups: result.TotalGroups}
}

func flowFieldChange(kind string, before, after *anomaly.RankedFlowField) flow.FieldChange {
	result := flow.FieldChange{Kind: kind}
	if before != nil {
		result.Key, result.Group = before.Key, before.Group
		result.Before = &flow.FieldObservation{Rank: before.Rank, Value: before.Value, Secondary: before.Secondary, Citation: before.Citation}
	}
	if after != nil {
		result.Key, result.Group = after.Key, after.Group
		result.After = &flow.FieldObservation{Rank: after.Rank, Value: after.Value, Secondary: after.Secondary, Citation: after.Citation}
	}
	return result
}

func flowFieldAuthorityDigest(capture *reportFlowCapture, settings flowFieldComparisonSettings, result capturedReportFlow) (string, error) {
	values, err := json.Marshal(struct {
		Tenant, View, Revision string
		SourceGeneration       int64
		TagRevision            int64
		InterfaceRoleDigest    string
		Filters                map[string]int64
	}{capture.TenantID, settings.View.ID, settings.View.Version, capture.SourceGeneration,
		result.Result.TagRevision, result.Result.RoleDigest, capture.FilterVersions})
	if err != nil {
		return "", err
	}
	digest := crypto.Hash(values)
	if len(digest) != 32 {
		return "", anomaly.ErrFlowFieldCoverage
	}
	return hex.EncodeToString(digest), nil
}
