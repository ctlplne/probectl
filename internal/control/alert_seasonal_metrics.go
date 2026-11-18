// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/promapi"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// CurrentSeasonalRule is the evaluator's explicit dispatch for a stored
// seasonal source. A stale source revision cannot trigger another model.
func (s alertTagMetricSource) CurrentSeasonalRule(ctx context.Context, rule alert.Rule, at time.Time) (alert.RuleMetricRead, error) {
	if s.deps.Queries == nil || s.pool == nil || s.tenant == "" || rule.TenantID != s.tenant || !rule.Enabled || !rule.HasSeasonalSource {
		return alert.RuleMetricRead{}, alert.ErrSeasonalSource
	}
	if tenant, ok := tenancy.FromContext(ctx); ok && tenant.String() != s.tenant {
		return alert.RuleMetricRead{}, tenancy.ErrNoTenant
	}
	if err := rule.Validate(); err != nil {
		return alert.RuleMetricRead{}, err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(s.tenant))
	return s.deps.Queries.readSeasonalMetricRule(ctx, rule, at)
}

func (s *Server) readSeasonalMetricRule(ctx context.Context, rule alert.Rule, at time.Time) (alert.RuleMetricRead, error) {
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return alert.RuleMetricRead{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	source, err := s.loadSeasonalRuleSource(ctx, rule, budget.MemoryBytes/8)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	model, err := source.Config.Model()
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	actor, err := source.CredentialCeiling(rule.TenantID)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	selected, notBefore, err := s.seasonalMetricSelection(ctx, actor, rule, source)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	scores, labels, err := s.compareSeasonalMetrics(ctx, actor, selected, model, at, notBefore)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	if _, err := s.loadSeasonalRuleSource(ctx, rule, budget.MemoryBytes/8); err != nil {
		return alert.RuleMetricRead{}, err
	}
	if _, _, err := s.seasonalMetricSelection(ctx, actor, rule, source); err != nil {
		return alert.RuleMetricRead{}, err
	}
	samples := make([]alert.Sample, 0, len(scores))
	for i := range scores {
		comparison := &scores[i]
		samples = append(samples, alert.Sample{Labels: labels[comparison.Observed.Subject], Value: comparison.Observed.Value, Seasonal: comparison})
	}
	return alert.RuleMetricRead{Samples: samples}, ctx.Err()
}

func (s *Server) seasonalMetricSelection(ctx context.Context, actor *auth.Principal, rule alert.Rule, source *alert.SeasonalSource) (alert.Rule, time.Time, error) {
	if source.Config.TestID == "" {
		return rule, time.Time{}, nil
	}
	version, err := s.seasonalTestRevision(ctx, actor, source.Config.TestID, source.TestRevision)
	if err != nil {
		return alert.Rule{}, time.Time{}, err
	}
	selected, err := bindSeasonalTestSelector(rule, source.Config.TestID)
	return selected, version, err
}

func (s *Server) loadSeasonalRuleSource(ctx context.Context, rule alert.Rule, memory int64) (*alert.SeasonalSource, error) {
	var source *alert.SeasonalSource
	err := tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		source, err = (store.AlertRules{}).GetSeasonalSource(ctx, sc, rule.ID, rule.UpdatedAt, memory)
		return err
	})
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, alert.ErrSeasonalSource
	}
	return source, nil
}

type seasonalMetricPopulation struct {
	features  []anomaly.Feature
	labels    map[string]map[string]string
	remaining int64
}

type seasonalMetricReadBudget struct {
	rows  int
	bytes int64
}

func (b *seasonalMetricReadBudget) charge(rows []promapi.ResultSeries) error {
	for _, series := range rows {
		const pointBytes = 64
		if len(series.Points) > b.rows || int64(len(series.Points)) > b.bytes/pointBytes {
			return apierror.Validation("complete seasonal history exceeds its read admission")
		}
		b.rows -= len(series.Points)
		b.bytes -= int64(len(series.Points)) * pointBytes
		for key, value := range series.Labels {
			b.bytes -= int64(len(key)) + int64(len(value)) + 128
			if b.bytes < 0 {
				return apierror.Validation("complete seasonal history exceeds its read admission")
			}
		}
	}
	return nil
}

// compareSeasonalMetrics uses the existing tenant-wide metric read permission.
// A caller for a configured test must first authorize and pin its exact test
// selector. No source permission is inferred from a label returned by TSDB.
func (s *Server) compareSeasonalMetrics(ctx context.Context, actor *auth.Principal, rule alert.Rule, model anomaly.WeeklySeasonalModel, at, notBefore time.Time) ([]anomaly.SeasonalComparison, map[string]map[string]string, error) {
	if tenant, ok := tenancy.FromContext(ctx); !ok || actor == nil || actor.TenantID != tenant.String() || rule.TenantID != actor.TenantID {
		return nil, nil, tenancy.ErrNoTenant
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil || s.fairnessGate == nil {
		return nil, nil, apierror.Unavailable("seasonal metric admission is unavailable")
	}
	if err := validateSeasonalMetricRead(rule, at); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if err := s.authorizeSeasonalMetricRead(ctx, actor); err != nil {
		return nil, nil, err
	}
	release, err := s.fairnessGate.BeginQuery(ctx, rule.TenantID)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	return s.compareAdmittedSeasonalMetrics(ctx, actor, rule, model, at, notBefore, budget)
}

func (s *Server) authorizeSeasonalMetricRead(ctx context.Context, actor *auth.Principal) error {
	current, err := loadCurrentUserAuthority(ctx, s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	return s.authorize(ctx, principal, "metrics.read", auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID})
}

func (s *Server) compareAdmittedSeasonalMetrics(ctx context.Context, actor *auth.Principal, rule alert.Rule, model anomaly.WeeklySeasonalModel, at, notBefore time.Time, budget flowstore.ExplorerBudget) ([]anomaly.SeasonalComparison, map[string]map[string]string, error) {
	population := seasonalMetricPopulation{labels: make(map[string]map[string]string), remaining: budget.MemoryBytes / 2}
	readBudget := seasonalMetricReadBudget{rows: budget.ReadRows, bytes: budget.ReadBytes}
	at = at.UTC().Truncate(time.Millisecond)
	notBefore = notBefore.UTC().Truncate(time.Millisecond)
	if !at.After(notBefore) {
		return nil, nil, ctx.Err()
	}
	windowBytes := min(budget.MemoryBytes/8, budget.ResponseBytes)
	current, err := s.readSeasonalMetricWindow(ctx, rule, seasonalReadStart(at.Add(-promapi.DefaultLookback), notBefore), at, min(windowBytes, readBudget.bytes))
	if err != nil {
		return nil, nil, err
	}
	if err := readBudget.charge(current); err != nil {
		return nil, nil, err
	}
	reads, err := population.addCurrentSamples(ctx, rule, model, current)
	if err != nil {
		return nil, nil, err
	}
	for _, read := range reads {
		after := seasonalReadStart(read.window.Start.Add(-time.Millisecond), notBefore)
		through := read.window.End.Add(-time.Millisecond)
		if !through.After(after) {
			continue
		}
		history, err := s.readSeasonalMetricWindow(ctx, rule, after, through, min(windowBytes, readBudget.bytes))
		if err != nil {
			return nil, nil, err
		}
		if err := readBudget.charge(history); err != nil {
			return nil, nil, err
		}
		if err := population.addHistory(ctx, rule, read.series, history); err != nil {
			return nil, nil, err
		}
	}
	compared, err := model.Compare(ctx, population.features, anomaly.Query{TenantID: rule.TenantID, Sensitivity: rule.Sensitivity})
	if err != nil {
		return nil, nil, err
	}
	if err := s.authorizeSeasonalMetricRead(ctx, actor); err != nil {
		return nil, nil, err
	}
	return compared, population.labels, nil
}

func seasonalReadStart(after, notBefore time.Time) time.Time {
	if notBefore.After(after) {
		return notBefore
	}
	return after
}

func validateSeasonalMetricRead(rule alert.Rule, at time.Time) error {
	if at.IsZero() || !promapi.ValidMetricName(rule.Metric) {
		return apierror.Validation("an exact metric and an admitted seasonal history window are required")
	}
	for key := range rule.Match {
		if !promapi.ValidLabelName(key) || key == promapi.TenantLabel || key == "__name__" {
			return apierror.Validation("seasonal metrics require exact nonreserved label names")
		}
	}
	return nil
}

func (s *Server) readSeasonalMetricWindow(ctx context.Context, rule alert.Rule, after, through time.Time, maxBytes int64) ([]promapi.ResultSeries, error) {
	if tenant, ok := tenancy.FromContext(ctx); !ok || tenant.String() != rule.TenantID {
		return nil, tenancy.ErrNoTenant
	}
	selector := promapi.Selector{Metric: rule.Metric}
	for key, value := range rule.Match {
		selector.Matchers = append(selector.Matchers, promapi.Matcher{Name: key, Op: "=", Value: value})
	}
	selector = promapi.ForceTenant(selector, rule.TenantID)
	if memory, ok := s.tsdbWriter.(*tsdb.Memory); ok {
		points, err := memory.ReadTenantMetricSamples(ctx, rule.TenantID, rule.Metric, rule.Match, after.UnixMilli(), through.UnixMilli(), maxBytes)
		if err != nil || len(points) == 0 {
			return nil, err
		}
		// The indexed read already bounded full memory and cardinality before
		// grouping. Every distinct series has at least one admitted point.
		return promapi.Range(points, selector, after.Add(time.Millisecond), through, len(points))
	}
	if s.promUpstream == nil {
		return nil, apierror.Unavailable("seasonal metric history is unavailable")
	}
	return s.promUpstream.ReadRawSamples(ctx, selector, after, through, maxBytes)
}

type seasonalMetricHistoryRead struct {
	window anomaly.SeasonalWindow
	series map[string]bool
}

func (p *seasonalMetricPopulation) addCurrentSamples(ctx context.Context, rule alert.Rule, model anomaly.WeeklySeasonalModel, result []promapi.ResultSeries) ([]seasonalMetricHistoryRead, error) {
	var reads []seasonalMetricHistoryRead
	byWindow := make(map[anomaly.SeasonalWindow]int)
	for _, series := range result {
		key, err := seasonalMetricIdentity(rule, series)
		if err != nil {
			return nil, err
		}
		if len(series.Points) == 0 {
			continue
		}
		point := series.Points[len(series.Points)-1]
		if err := p.addSample(ctx, rule, key, point); err != nil {
			return nil, err
		}
		p.labels[key] = series.Labels
		for _, window := range model.ComparableWindows(time.UnixMilli(point.TimeMillis)) {
			index, seen := byWindow[window]
			if !seen {
				index = len(reads)
				byWindow[window] = index
				reads = append(reads, seasonalMetricHistoryRead{window: window, series: make(map[string]bool)})
			}
			reads[index].series[key] = true
		}
	}
	return reads, ctx.Err()
}

func (p *seasonalMetricPopulation) addHistory(ctx context.Context, rule alert.Rule, selected map[string]bool, result []promapi.ResultSeries) error {
	for _, series := range result {
		key, err := seasonalMetricIdentity(rule, series)
		if err != nil {
			return err
		}
		if !selected[key] {
			continue
		}
		for _, point := range series.Points {
			if err := p.addSample(ctx, rule, key, point); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func seasonalMetricIdentity(rule alert.Rule, series promapi.ResultSeries) (string, error) {
	if series.Metric != rule.Metric || series.Labels[promapi.TenantLabel] != rule.TenantID {
		return "", anomaly.ErrCrossTenantFeature
	}
	for key, value := range rule.Match {
		if series.Labels[key] != value {
			return "", apierror.Forbidden("seasonal metric sample falls outside the configured match")
		}
	}
	// Carry the complete label set into the fingerprint, including the tenant.
	key := tsdb.SeriesIdentity(rule.Metric, series.Labels)
	digest := crypto.Hash([]byte(key))
	if len(digest) != 32 {
		return "", apierror.Unavailable("seasonal metric source identity is unavailable")
	}
	return hex.EncodeToString(digest), nil
}

func (p *seasonalMetricPopulation) addSample(ctx context.Context, rule alert.Rule, key string, point promapi.Point) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	const accountedBytes = 512
	if p.remaining < accountedBytes {
		return apierror.Validation("complete seasonal history exceeds its memory admission")
	}
	p.remaining -= accountedBytes
	at := time.UnixMilli(point.TimeMillis).UTC()
	p.features = append(p.features, anomaly.Feature{TenantID: rule.TenantID, Plane: "metrics", Source: "tsdb", Subject: key,
		Metric: rule.Metric, TS: at, Value: point.Value, Citation: "metric:" + key + "@" + at.Format(time.RFC3339Nano)})
	return nil
}
