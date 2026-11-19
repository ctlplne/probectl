// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/promapi"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) readSeasonalFlowRule(ctx context.Context, rule alert.Rule, source *alert.SeasonalSource, actor *auth.Principal, model anomaly.WeeklySeasonalModel, at time.Time) (_ alert.RuleMetricRead, readErr error) {
	if source.Config.Flow == nil || rule.Metric != alert.SeasonalFlowMetric {
		return alert.RuleMetricRead{}, alert.ErrSeasonalSource
	}
	_, end := model.LatestCompletedSlot(at)
	var due bool
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		due, err = (store.AlertRules{}).SeasonalFlowWindowDue(ctx, sc, rule.ID, rule.UpdatedAt, end)
		return err
	})
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	if !due {
		return alert.RuleMetricRead{Skip: true}, nil
	}
	current, err := s.readSeasonalFlow(ctx, actor, rule, *source.Config.Flow, model, at)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	defer func() {
		if readErr != nil {
			current.Capture.Close()
		}
	}()
	publication, err := s.seasonalFlowPublication(ctx, rule, current, end)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	samples := make([]alert.Sample, 0, len(current.Scores))
	for _, result := range current.Scores {
		comparison := anomaly.SeasonalComparison{
			Observed: anomaly.Feature{TenantID: rule.TenantID, Source: "saved-explorer", Plane: "flow", Subject: result.Subject, Metric: rule.Metric, TS: current.At},
			State:    result.Result.State, ComparableDays: result.Result.ComparableDays, RequiredPeriods: result.Result.RequiredPeriods, Evidence: result.Result.Calendar, Exact: result.Result.Band,
			TrainingWindow: result.Result.TrainingWindow, Citations: result.Result.Citations,
		}
		samples = append(samples, alert.Sample{Labels: map[string]string{promapi.TenantLabel: rule.TenantID}, Seasonal: &comparison, SeasonalDirection: source.Config.Direction})
	}
	return alert.RuleMetricRead{Samples: samples, SeasonalPublication: publication}, ctx.Err()
}

func (s *Server) seasonalFlowPublication(ctx context.Context, rule alert.Rule, current ownedSeasonalFlowRead, end time.Time) (*alert.SeasonalReadPublication, error) {
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	raw, err := encodeSeasonalFlowScope(ctx, current.Capture, budget.MemoryBytes/8)
	if err != nil {
		return nil, err
	}
	recheck := func(ctx context.Context, sc tenancy.Scope) error {
		return s.validateReportSourcePublication(store.WithReportSourceAuditLock(ctx, sc), sc, current.Principal, current.Capture)
	}
	finish := func(ctx context.Context) error {
		if bound, ok := tenancy.FromContext(ctx); ok && bound.String() != rule.TenantID {
			return tenancy.ErrNoTenant
		}

		ctx, cancel := context.WithTimeout(tenancy.WithTenant(ctx, tenancy.ID(rule.TenantID)), budget.ExecutionLimit)
		defer cancel()
		return tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.AlertRules{}).WithSeasonalPublication(ctx, sc, rule.ID, rule.UpdatedAt, budget.MemoryBytes/8,
				func(ctx context.Context, sc tenancy.Scope, source *alert.SeasonalSource) error {
					if source.Config.Flow == nil {
						return alert.ErrSeasonalSource
					}
					if err := recheck(ctx, sc); err != nil {
						return err
					}
					return (store.AlertRules{}).FinishSeasonalFlowWindow(ctx, sc, rule.ID, rule.UpdatedAt, end)
				})
		})
	}
	return &alert.SeasonalReadPublication{Revalidate: recheck, Finish: finish, Close: current.Capture.Close, Scope: raw}, nil
}

// Retain only the requirements for the exact original reader. The capture's
// rows, policies and admission leases never enter this stored proof.
type storedSeasonalFlowScope struct {
	Version          int                        `json:"version"`
	TenantID         string                     `json:"tenant_id"`
	SourceGeneration int64                      `json:"source_generation"`
	Inputs           []reportFlowInput          `json:"inputs,omitempty"`
	Timeline         *seasonalScopeTimeline     `json:"timeline,omitempty"`
	Permissions      []string                   `json:"permissions"`
	Contexts         []reportContextRequirement `json:"contexts"`
	ContextsCaptured bool                       `json:"contexts_captured"`
	ContextSources   bool                       `json:"context_sources"`
	FilterVersions   map[string]int64           `json:"filter_versions"`
}

func encodeSeasonalFlowScope(ctx context.Context, c *reportFlowCapture, memory int64) ([]byte, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || c == nil || c.TenantID != tenant.String() || c.SourceGeneration < 1 || len(c.Inputs) == 0 {
		return nil, alert.ErrSeasonalSource
	}
	if err := admitSeasonalFlowScopeEncoding(ctx, c, memory); err != nil {
		return nil, err
	}
	req := storedSeasonalFlowScope{Version: 1, TenantID: c.TenantID, SourceGeneration: c.SourceGeneration, Inputs: c.Inputs, Permissions: c.Permissions,
		Contexts: c.Contexts, ContextsCaptured: c.ContextsCaptured, ContextSources: c.ContextSources, FilterVersions: c.FilterVersions}
	if len(c.Inputs) > seasonalFlowLegacyWindows {
		timeline, err := compactSeasonalFlowTimeline(ctx, c.Inputs)
		if err != nil {
			return nil, err
		}
		req.Version, req.Inputs, req.Timeline = 2, nil, timeline
		if timeline.SharedRouting != nil {
			req.Version = 3
		}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := admitFlowSnapshotValidity(ctx, body, alert.SeasonalFlowScopeBytes, memory); err != nil {
		return nil, err
	}
	return body, ctx.Err()
}

// Charge variable-size fields before marshaling. Use the existing exact raw
// JSON admission after serialization, including escaping and token costs.
func admitSeasonalFlowScopeEncoding(ctx context.Context, capture *reportFlowCapture, memory int64) error {
	left := min(int64(alert.SeasonalFlowScopeBytes), memory/4)
	charge := func(base int64, values ...string) bool {
		for _, value := range values {
			base += int64(len(value))
		}
		left -= base
		return left > 0 && ctx.Err() == nil
	}
	if len(capture.Inputs) > anomaly.SeasonalFlowMaximumWindows || !charge(128, capture.TenantID) {
		return alert.ErrSeasonalSource
	}
	for _, permission := range capture.Permissions {
		if !charge(2, permission) {
			return alert.ErrSeasonalSource
		}
	}
	compact := len(capture.Inputs) > seasonalFlowLegacyWindows
	sharedRouting := sharedSeasonalRouting(capture.Inputs)
	for i, input := range capture.Inputs {
		if !charge(72) || ((!compact || i == 0) && !charge(0, input.ID, input.Version, input.TagRevision)) {
			return alert.ErrSeasonalSource
		}
		if input.Routing == nil || (compact && sharedRouting != nil && i != 0) {
			continue
		}
		for _, row := range input.Routing.Captures {
			if !charge(80, row.Sender, row.Raw, row.Key, row.Exporter, row.Source, row.Destination, row.Protocol) {
				return alert.ErrSeasonalSource
			}
		}
	}
	for id := range capture.FilterVersions {
		if !charge(4, id) {
			return alert.ErrSeasonalSource
		}
	}
	for _, requirement := range capture.Contexts {
		if !charge(18, requirement.ContextID) {
			return alert.ErrSeasonalSource
		}
		for key, value := range requirement.Resource {
			if !charge(4, key, value) {
				return alert.ErrSeasonalSource
			}
		}
		for _, permission := range requirement.Permissions {
			if !charge(2, permission) {
				return alert.ErrSeasonalSource
			}
		}
	}
	return ctx.Err()
}

func decodeSeasonalFlowScope(ctx context.Context, raw []byte, config alert.SeasonalBaselineInput, observed time.Time, memory int64) (*reportFlowCapture, error) {
	capture, err := decodeStoredFlowScope(ctx, raw, memory)
	if err != nil {
		return nil, err
	}
	if err := validateStoredSeasonalFlowInputs(ctx, capture.Inputs, config, observed, slices.Contains(capture.Permissions, permTagsRead), memory); err != nil {
		return nil, err
	}
	return capture, ctx.Err()
}

// decodeStoredFlowScope validates the shared private saved-flow lineage.
// Each receipt reader then proves the exact clocks for its own source model.
func decodeStoredFlowScope(ctx context.Context, raw []byte, memory int64) (*reportFlowCapture, error) {
	if err := admitFlowSnapshotValidity(ctx, raw, alert.SeasonalFlowScopeBytes, memory); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var req storedSeasonalFlowScope
	if err := decoder.Decode(&req); err != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, alert.ErrSeasonalSource
	}

	bound, ok := tenancy.FromContext(ctx)
	if !ok || !reportRequirementUUID(req.TenantID) || req.TenantID != bound.String() || req.SourceGeneration < 1 {
		return nil, alert.ErrSeasonalSource
	}
	inputs, err := req.expandedInputs(ctx, memory)
	if err != nil {
		return nil, err
	}
	capture := &reportFlowCapture{TenantID: req.TenantID, SourceGeneration: req.SourceGeneration, Inputs: inputs, Permissions: req.Permissions,
		Contexts: req.Contexts, ContextsCaptured: req.ContextsCaptured, ContextSources: req.ContextSources, FilterVersions: req.FilterVersions}
	if err := validateReportCapturedSources(capture); err != nil {
		return nil, err
	}
	for _, input := range inputs {
		if input.RoutingSource && !req.ContextSources {
			return nil, alert.ErrSeasonalSource
		}
	}
	for _, requirement := range req.Contexts {
		if err := validateStoredReportContext(req.TenantID, requirement); err != nil {
			return nil, err
		}
	}
	for id, revision := range req.FilterVersions {
		if !reportRequirementUUID(id) || revision <= 0 {
			return nil, alert.ErrSeasonalSource
		}
	}
	return capture, ctx.Err()
}

func validateStoredSeasonalFlowInputs(ctx context.Context, inputs []reportFlowInput, config alert.SeasonalBaselineInput, observed time.Time, usesTags bool, memory int64) error {
	if len(inputs) < 1 || len(inputs) > anomaly.SeasonalFlowMaximumWindows || observed.IsZero() || config.Flow == nil {
		return alert.ErrSeasonalSource
	}
	last := inputs[len(inputs)-1]
	model, err := config.Model()
	if err != nil || !exactSeasonalObservedAt(last.To).Equal(observed) {
		return alert.ErrSeasonalSource
	}
	sampleClock, end := model.LatestCompletedSlot(last.To)
	clocks := append(model.ComparableCompleteEnds(sampleClock), end)
	slices.SortFunc(clocks, time.Time.Compare)
	if !sampleClock.Equal(observed) || len(clocks) != len(inputs) {
		return alert.ErrSeasonalSource
	}
	validatedRouting := map[*flowRoutingSnapshotValidity]bool{}
	for i, input := range inputs {
		if input.ID != config.Flow.ViewID || input.Version != config.Flow.ViewVersion || input.Period != "current" || !input.To.Equal(clocks[i]) ||
			input.To.Sub(input.From) != last.To.Sub(last.From) || input.TagRevision != last.TagRevision ||
			!input.TagAsOf.Equal(last.TagAsOf) || (i > 0 && !inputs[i-1].To.Before(input.To)) {
			return alert.ErrSeasonalSource
		}
		checked := input
		if input.RoutingSource && validatedRouting[input.Routing] {
			// The compact document expands one immutable proof to each
			// complete window. Validate the shared proof on its first use.
			checked.Routing, checked.RoutingSource = nil, false
		}
		if err := validateReportSourceInputs(ctx, []reportFlowInput{checked}, usesTags, memory); err != nil {
			return err
		}
		if input.RoutingSource {
			validatedRouting[input.Routing] = true
		}
	}
	return ctx.Err()
}
