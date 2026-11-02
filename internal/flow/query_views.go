// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrQueryViewNotFound = errors.New("saved flow query not found")
	ErrQueryViewConflict = errors.New("saved flow query version conflict")
	ErrQueryViewBudget   = errors.New("saved flow query storage byte budget exceeded")
	ErrQueryViewStaleTag = errors.New("saved flow query tag changed; refresh the view")
)

type QueryViewTime struct {
	Mode            string `json:"mode"`
	LookbackSeconds int64  `json:"lookback_seconds,omitempty"`
}

type QueryViewComparison struct {
	Mode string    `json:"mode"`
	From time.Time `json:"from,omitempty"`
	To   time.Time `json:"to,omitempty"`
}

// QueryViewDisplay only changes presentation of authorized frozen results.
// It carries no source, scope, permission or execution-budget override.
type QueryViewDisplay struct {
	TimeStyle         string   `json:"time_style"`
	PercentBasis      string   `json:"percent_basis"`
	HorizonScale      string   `json:"horizon_scale"`
	TotalOverlay      bool     `json:"total_overlay"`
	LogMetrics        []string `json:"log_metrics"`
	SyncAxes          bool     `json:"sync_axes"`
	OneChartPerSeries bool     `json:"one_chart_per_series"`
	ChartsPerRow      int      `json:"charts_per_row"`
	ChartHeight       string   `json:"chart_height"`
}

// QueryViewDefinition is reusable configuration, never cached result data or
// authorization. Relative bounds are materialized afresh at execution time.
type QueryViewDefinition struct {
	Name               string               `json:"name"`
	Description        string               `json:"description"`
	Labels             []string             `json:"labels"`
	Visibility         string               `json:"visibility"`
	Plan               QueryPlan            `json:"plan"`
	Time               QueryViewTime        `json:"time"`
	Comparison         *QueryViewComparison `json:"comparison,omitempty"`
	AutoRefreshSeconds int                  `json:"auto_refresh_seconds"`
	Display            *QueryViewDisplay    `json:"display,omitempty"`
	// TagIDs pins the tenant's immutable definition IDs for every tag field in
	// the saved plan. A later rename or replacement cannot silently retarget it.
	TagIDs map[string]string `json:"tag_ids,omitempty"`
}

type SaveQueryView struct {
	ID         string              `json:"id,omitempty"`
	Version    string              `json:"version,omitempty"`
	Definition QueryViewDefinition `json:"definition"`
}

type SavedQueryView struct {
	ID           string              `json:"id"`
	TenantID     string              `json:"-"`
	OwnerID      string              `json:"owner_id"`
	Version      string              `json:"version"`
	Definition   QueryViewDefinition `json:"definition"`
	CreatedAt    time.Time           `json:"created_at"`
	UpdatedAt    time.Time           `json:"updated_at"`
	Favorite     bool                `json:"favorite"`
	LastOpenedAt *time.Time          `json:"last_opened_at,omitempty"`
}

// QueryViewVersion keeps optimistic revisions exact on every transport.
func QueryViewVersion(text string) (int64, error) {
	version, err := strconv.ParseInt(text, 10, 64)
	if err != nil || version < 1 || strconv.FormatInt(version, 10) != text {
		return 0, ErrQueryViewConflict
	}
	return version, nil
}

func NormalizeSaveQueryView(input SaveQueryView, now time.Time) (SaveQueryView, error) {
	return normalizeSaveQueryView(input, now, NormalizeQueryViewDefinition)
}

// NormalizeSaveQueryViewWithVocabulary accepts only fields from one tenant's
// request-local tag registry. The caller must authenticate that tenant first.
func NormalizeSaveQueryViewWithVocabulary(input SaveQueryView, now time.Time, vocabulary QueryVocabulary) (SaveQueryView, error) {
	return normalizeSaveQueryView(input, now, func(definition QueryViewDefinition, at time.Time) (QueryViewDefinition, error) {
		return NormalizeQueryViewDefinitionWithVocabulary(definition, at, vocabulary)
	})
}

func normalizeSaveQueryViewForTenant(ctx context.Context, tenant string, input SaveQueryView, now time.Time) (SaveQueryView, error) {
	vocabulary, bound, err := QueryVocabularyFromContext(ctx, tenant)
	if err != nil {
		return SaveQueryView{}, err
	}
	if bound {
		return NormalizeSaveQueryViewWithVocabulary(input, now, vocabulary)
	}
	return NormalizeSaveQueryView(input, now)
}

func normalizeQueryViewDefinitionForTenant(ctx context.Context, tenant string, input QueryViewDefinition, now time.Time) (QueryViewDefinition, error) {
	vocabulary, bound, err := QueryVocabularyFromContext(ctx, tenant)
	if err != nil {
		return QueryViewDefinition{}, err
	}
	if bound {
		return NormalizeQueryViewDefinitionWithVocabulary(input, now, vocabulary)
	}
	return NormalizeQueryViewDefinition(input, now)
}

func validateQueryViewTagsForTenant(ctx context.Context, tenant string, definition QueryViewDefinition, reader QueryFilterReader) error {
	vocabulary, bound, err := QueryVocabularyFromContext(ctx, tenant)
	if err != nil {
		return err
	}
	var resolved ResolvedQueryFilters
	if bound {
		resolved, err = ResolveQueryFiltersWithVocabulary(ctx, tenant, definition.Plan.Filter, reader, "", vocabulary)
	} else {
		resolved, err = ResolveQueryFilters(ctx, tenant, definition.Plan.Filter, reader, "")
	}
	if err != nil {
		return err
	}
	if !bound {
		if len(definition.TagIDs) > 0 {
			return ErrQueryViewStaleTag
		}
		return nil
	}
	plan := definition.Plan
	plan.Filter = resolved.Expression
	return VerifyQueryViewTagIDs(definition.TagIDs, plan, vocabulary)
}

func normalizeSaveQueryView(input SaveQueryView, now time.Time,
	normalize func(QueryViewDefinition, time.Time) (QueryViewDefinition, error)) (SaveQueryView, error) {
	input.ID = strings.TrimSpace(input.ID)
	if input.ID == "" {
		if input.Version != "" {
			return SaveQueryView{}, ErrQueryViewConflict
		}
	} else if _, err := QueryViewVersion(input.Version); err != nil {
		return SaveQueryView{}, err
	}
	normalized, err := normalize(input.Definition, now)
	if err != nil {
		return SaveQueryView{}, err
	}
	input.Definition = normalized
	return input, nil
}

func NormalizeQueryViewDefinition(input QueryViewDefinition, now time.Time) (QueryViewDefinition, error) {
	return normalizeQueryViewDefinition(input, now, MaterializeQueryView)
}

func NormalizeQueryViewDefinitionWithVocabulary(input QueryViewDefinition, now time.Time, vocabulary QueryVocabulary) (QueryViewDefinition, error) {
	return normalizeQueryViewDefinition(input, now, func(definition QueryViewDefinition, at time.Time) (QueryPlan, *QueryPlan, error) {
		return MaterializeQueryViewWithVocabulary(definition, at, vocabulary)
	})
}

func normalizeQueryViewDefinition(input QueryViewDefinition, now time.Time,
	materialize func(QueryViewDefinition, time.Time) (QueryPlan, *QueryPlan, error)) (QueryViewDefinition, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if input.Name == "" || len(input.Name) > 256 || len(input.Description) > 4096 {
		return QueryViewDefinition{}, errors.New("saved flow query needs a name of1-256 bytes and description at most4096 bytes")
	}
	if input.Visibility == "" {
		input.Visibility = "private"
	}
	if input.Visibility != "private" && input.Visibility != "tenant" {
		return QueryViewDefinition{}, errors.New("saved flow query visibility must be private or tenant")
	}
	labels := []string{}
	seen := map[string]bool{}
	labelBytes := 0
	for _, label := range input.Labels {
		label = strings.TrimSpace(label)
		if label == "" || len(label) > 256 {
			return QueryViewDefinition{}, errors.New("saved flow query labels must have1-256 bytes")
		}
		if !seen[label] {
			seen[label] = true
			labels = append(labels, label)
			labelBytes += len(label) + 8
		}
		if labelBytes > 16384 {
			return QueryViewDefinition{}, ErrQueryViewBudget
		}
	}
	sort.Strings(labels)
	input.Labels = labels
	if input.AutoRefreshSeconds != 0 && input.AutoRefreshSeconds != 60 && input.AutoRefreshSeconds != 90 && input.AutoRefreshSeconds != 120 {
		return QueryViewDefinition{}, errors.New("saved flow query refresh must be off,60,90 or120 seconds")
	}
	if input.Plan.Cursor != "" {
		return QueryViewDefinition{}, errors.New("saved flow queries cannot contain a transient result cursor")
	}
	if input.Time.Mode == "" {
		input.Time.Mode = "absolute"
	}
	plan, comparison, err := materialize(input, now)
	if err != nil {
		return QueryViewDefinition{}, err
	}
	input.Plan = plan
	if input.Display != nil {
		display, err := NormalizeQueryViewDisplay(*input.Display, plan)
		if err != nil {
			return QueryViewDefinition{}, err
		}
		input.Display = &display
	}
	if input.Time.Mode == "lookback" {
		input.Plan.From = time.Time{}
		input.Plan.To = time.Time{}
	}
	if comparison != nil {
		input.Comparison = &QueryViewComparison{Mode: input.Comparison.Mode, From: comparison.From, To: comparison.To}
		if input.Comparison.Mode == "preceding" {
			input.Comparison.From = time.Time{}
			input.Comparison.To = time.Time{}
		}
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return QueryViewDefinition{}, err
	}
	if len(encoded) > MaxPlanGrammarBytes {
		return QueryViewDefinition{}, ErrQueryViewBudget
	}
	return input, nil
}

// MaterializeQueryView uses one supplied clock for the current and previous
// windows. No store read, tenant selection or resource-budget override occurs.
func MaterializeQueryView(input QueryViewDefinition, now time.Time) (QueryPlan, *QueryPlan, error) {
	return materializeQueryView(input, now, NormalizeQueryPlan)
}

func MaterializeQueryViewWithVocabulary(input QueryViewDefinition, now time.Time, vocabulary QueryVocabulary) (QueryPlan, *QueryPlan, error) {
	return materializeQueryView(input, now, func(plan QueryPlan, at time.Time) (QueryPlan, error) {
		return NormalizeQueryPlanWithVocabulary(plan, at, vocabulary)
	})
}

func materializeQueryView(input QueryViewDefinition, now time.Time,
	normalize func(QueryPlan, time.Time) (QueryPlan, error)) (QueryPlan, *QueryPlan, error) {
	plan := input.Plan
	if plan.Cursor != "" {
		return QueryPlan{}, nil, errors.New("saved flow queries cannot contain a transient result cursor")
	}
	switch input.Time.Mode {
	case "", "absolute":
		if input.Time.LookbackSeconds != 0 {
			return QueryPlan{}, nil, errors.New("absolute saved query cannot contain lookback seconds")
		}
	case "lookback":
		if input.Time.LookbackSeconds < 60 || input.Time.LookbackSeconds > math.MaxInt64/int64(time.Second) {
			return QueryPlan{}, nil, errors.New("saved query lookback is outside the supported duration range")
		}
		plan.To = now.UTC()
		plan.From = plan.To.Add(-time.Duration(input.Time.LookbackSeconds) * time.Second)
	default:
		return QueryPlan{}, nil, errors.New("saved flow query time mode must be absolute or lookback")
	}
	plan, err := normalize(plan, now)
	if err != nil {
		return QueryPlan{}, nil, err
	}
	if !plan.From.Before(plan.To) {
		return QueryPlan{}, nil, errors.New("saved flow query window must have positive duration")
	}
	if input.Comparison == nil {
		return plan, nil, nil
	}
	previous := plan
	switch input.Comparison.Mode {
	case "absolute":
		if input.Comparison.From.IsZero() || input.Comparison.To.IsZero() {
			return QueryPlan{}, nil, errors.New("saved query comparison requires explicit bounds")
		}
		previous.From = input.Comparison.From
		previous.To = input.Comparison.To
	case "preceding":
		if !input.Comparison.From.IsZero() || !input.Comparison.To.IsZero() {
			return QueryPlan{}, nil, errors.New("preceding comparison cannot contain absolute bounds")
		}
		previous.To = plan.From
		previous.From = previous.To.Add(-plan.To.Sub(plan.From))
	default:
		return QueryPlan{}, nil, errors.New("saved query comparison mode must be absolute or preceding")
	}
	previous, err = normalize(previous, now)
	if err != nil {
		return QueryPlan{}, nil, err
	}
	if !previous.From.Before(previous.To) {
		return QueryPlan{}, nil, errors.New("saved query comparison window must have positive duration")
	}
	return plan, &previous, nil
}

// NormalizeQueryViewDisplay validates presentation against an already normalized
// plan. Explorer views and question proposals use the same display vocabulary;
// no presentation setting grants access or changes source execution policy.
func NormalizeQueryViewDisplay(input QueryViewDisplay, plan QueryPlan) (QueryViewDisplay, error) {
	display := input
	if display.TimeStyle == "" {
		display.TimeStyle = "line"
	}
	if !slices.Contains([]string{"line", "stacked_area", "stacked_columns", "percent_area", "horizon"}, display.TimeStyle) {
		return QueryViewDisplay{}, errors.New("flow display time style must be line,stacked_area,stacked_columns,percent_area or horizon")
	}
	if display.HorizonScale == "" {
		display.HorizonScale = "shared"
	}
	if !slices.Contains([]string{"shared", "lane"}, display.HorizonScale) {
		return QueryViewDisplay{}, errors.New("flow horizon scale must be shared or lane")
	}
	if display.PercentBasis == "" {
		display.PercentBasis = "returned"
	}
	if !slices.Contains([]string{"returned", "visible"}, display.PercentBasis) {
		return QueryViewDisplay{}, errors.New("flow display percentage basis must be returned or visible")
	}
	if display.ChartsPerRow == 0 {
		display.ChartsPerRow = 1
	}
	if display.ChartsPerRow < 1 || display.ChartsPerRow > 4 {
		return QueryViewDisplay{}, errors.New("flow display charts per row must be1–4")
	}
	if display.ChartHeight == "" {
		display.ChartHeight = "medium"
	}
	if !slices.Contains([]string{"short", "medium", "tall"}, display.ChartHeight) {
		return QueryViewDisplay{}, errors.New("flow display chart height must be short,medium or tall")
	}
	known := map[string]bool{}
	for _, metric := range plan.Metrics {
		if metric.Role != "additional" {
			known[metric.Measure+":"+metric.Calculation] = true
		}
	}
	if len(display.LogMetrics) > 4 {
		return QueryViewDisplay{}, errors.New("flow display logarithmic metrics exceed selected plotted metrics")
	}
	logs := []string{}
	for _, key := range display.LogMetrics {
		if !known[key] {
			return QueryViewDisplay{}, errors.New("flow display logarithmic metric must be a selected plotted metric")
		}
		if !slices.Contains(logs, key) {
			logs = append(logs, key)
		}
	}
	sort.Strings(logs)
	display.LogMetrics = logs
	return display, nil
}
