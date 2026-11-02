// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"slices"
	"strings"
	"time"
)

// Public reach is independent of execution-cost budgets (D102/D103).
const (
	MaxPlanDimensions       = 8
	MaxPlanMatrixDimensions = 8
	MaxPlanMatrixDepth      = 15
	MaxPlanChartSeries      = 40
	MaxPlanChartRows        = 350
	MaxPlanTableRows        = 50000
	MaxPlanPageRows         = 5000
	MinPlanBucketSeconds    = 60
	MaxPlanBucketSeconds    = 604800
	MaxPlanGrammarBytes     = 2 << 20
)

// QueryPlan is the shared structured flow grammar for every user surface.
// Retention, physical storage, tenant, privileges and cost are server-owned.
type QueryPlan struct {
	From             time.Time         `json:"from"`
	To               time.Time         `json:"to"`
	GroupBy          []string          `json:"group_by"`
	MatrixWith       []string          `json:"matrix_with,omitempty"`
	Filter           *QueryFilterGroup `json:"filter,omitempty"`
	Metrics          []QueryMetric     `json:"metrics"`
	View             string            `json:"view"`
	DataSeries       string            `json:"dataseries"`
	BucketSeconds    int               `json:"bucket_seconds"`
	SeriesDepth      int               `json:"series_depth"`
	MatrixDepth      int               `json:"matrix_depth,omitempty"`
	RowLimit         int               `json:"row_limit"`
	PageSize         int               `json:"page_size"`
	Cursor           string            `json:"cursor,omitempty"`
	IPv4PrefixLength *int              `json:"ipv4_prefix_length,omitempty"`
	IPv6PrefixLength *int              `json:"ipv6_prefix_length,omitempty"`
}

// NormalizeQueryPlan validates the public shape without guessing tenant
// retention or imposing a time-range cap. Storage resolves coverage separately.
func NormalizeQueryPlan(plan QueryPlan, now time.Time) (QueryPlan, error) {
	return normalizeQueryPlan(plan, now, LookupQueryField)
}

func NormalizeQueryPlanWithVocabulary(plan QueryPlan, now time.Time, vocabulary QueryVocabulary) (QueryPlan, error) {
	return normalizeQueryPlan(plan, now, vocabulary.Lookup)
}

func normalizeQueryPlan(plan QueryPlan, now time.Time, lookup func(string) (QueryField, bool)) (QueryPlan, error) {
	if plan.To.IsZero() {
		plan.To = now
	}
	plan.To = plan.To.UTC()
	if plan.From.IsZero() {
		plan.From = plan.To.Add(-time.Hour)
	}
	plan.From = plan.From.UTC()
	if !plan.From.Before(plan.To) {
		return QueryPlan{}, errors.New("flow range must have from before to")
	}
	var err error
	plan.GroupBy, err = normalizePlanDimensionsWithLookup(plan.GroupBy, MaxPlanDimensions, lookup)
	if err != nil {
		return QueryPlan{}, err
	}
	plan.MatrixWith, err = normalizePlanDimensionsWithLookup(plan.MatrixWith, MaxPlanMatrixDimensions, lookup)
	if err != nil {
		return QueryPlan{}, err
	}
	plan.View = strings.ToLower(strings.TrimSpace(plan.View))
	if plan.View == "" {
		plan.View = "table"
	}
	if !slices.Contains([]string{"table", "bar", "line", "timeline", "matrix"}, plan.View) {
		return QueryPlan{}, errors.New("unsupported flow view")
	}
	if plan.View != "matrix" && len(plan.MatrixWith) > 0 {
		return QueryPlan{}, errors.New("matrix_with requires the matrix view")
	}
	if plan.View == "matrix" && (len(plan.GroupBy) == 0 || len(plan.MatrixWith) == 0) {
		return QueryPlan{}, errors.New("matrix requires row and column dimensions")
	}
	plan.Filter, err = normalizeQueryFilterGroup(plan.Filter, lookup)
	if err != nil {
		return QueryPlan{}, err
	}
	plan.Metrics, err = NormalizeQueryMetrics(plan.Metrics)
	if err != nil {
		return QueryPlan{}, err
	}
	plan.DataSeries = strings.ToLower(strings.TrimSpace(plan.DataSeries))
	if plan.DataSeries == "" {
		plan.DataSeries = "auto"
	}
	if !slices.Contains([]string{"auto", "raw", "rollup"}, plan.DataSeries) {
		return QueryPlan{}, errors.New("flow dataseries must be auto, raw or rollup")
	}
	if plan.BucketSeconds == 0 {
		plan.BucketSeconds = MinPlanBucketSeconds
	}
	if plan.BucketSeconds < MinPlanBucketSeconds || plan.BucketSeconds > MaxPlanBucketSeconds {
		return QueryPlan{}, errors.New("flow bucket width must be between one minute and one week")
	}
	if plan.SeriesDepth == 0 {
		plan.SeriesDepth = MaxPlanChartSeries
	}
	if plan.SeriesDepth < 1 || plan.SeriesDepth > MaxPlanChartSeries {
		return QueryPlan{}, errors.New("flow chart depth must be between 1 and 40 series")
	}
	if plan.MatrixDepth == 0 {
		plan.MatrixDepth = MaxPlanMatrixDepth
	}
	if plan.MatrixDepth < 1 || plan.MatrixDepth > MaxPlanMatrixDepth {
		return QueryPlan{}, errors.New("flow matrix depth must be between 1 and 15 values per axis")
	}
	maxRows := MaxPlanChartRows
	if plan.View == "table" {
		maxRows = MaxPlanTableRows
	}
	if plan.RowLimit == 0 {
		plan.RowLimit = min(100, maxRows)
	}
	if plan.RowLimit < 1 || plan.RowLimit > maxRows {
		return QueryPlan{}, errors.New("flow detail rows must be 1-50000 for tables or 1-350 beside charts")
	}
	if plan.PageSize == 0 {
		plan.PageSize = min(1000, plan.RowLimit)
	}
	if plan.PageSize < 1 || plan.PageSize > MaxPlanPageRows || plan.PageSize > plan.RowLimit {
		return QueryPlan{}, errors.New("flow page size must be positive and no larger than 5000 or the selected row limit")
	}
	if len(plan.Cursor) > 4096 {
		return QueryPlan{}, errors.New("flow cursor exceeds its encoded size budget")
	}
	for _, prefix := range []struct {
		value    **int
		def, max int
	}{{&plan.IPv4PrefixLength, 24, 32}, {&plan.IPv6PrefixLength, 48, 128}} {
		value := prefix.def
		if *prefix.value != nil {
			value = **prefix.value
		}
		if value < 0 || value > prefix.max {
			return QueryPlan{}, errors.New("invalid flow address prefix length")
		}
		copyValue := value
		*prefix.value = &copyValue
	}
	return plan, nil
}

func normalizePlanDimensionsWithLookup(input []string, limit int, lookup func(string) (QueryField, bool)) ([]string, error) {
	if len(input) > limit {
		return nil, errors.New("flow grouping and each matrix axis support at most eight dimensions")
	}
	out := make([]string, 0, len(input))
	for _, name := range input {
		field, ok := lookup(name)
		if !ok {
			return nil, errors.New("unsupported flow grouping field")
		}
		if slices.Contains(out, field.Name) {
			return nil, errors.New("duplicate flow dimension on an axis")
		}
		out = append(out, field.Name)
	}
	return out, nil
}

// QueryPlanPermissions includes joined metadata across matrix axes and nested
// conditions. Resolve saved references before calling it and enforce RBAC/ABAC.
func QueryPlanPermissions(plan QueryPlan) []string {
	return queryPlanPermissions(plan, LookupQueryField)
}

func QueryPlanPermissionsWithVocabulary(plan QueryPlan, vocabulary QueryVocabulary) []string {
	return queryPlanPermissions(plan, vocabulary.Lookup)
}

func queryPlanPermissions(plan QueryPlan, lookup func(string) (QueryField, bool)) []string {
	names := append(append(append([]string{}, plan.GroupBy...), plan.MatrixWith...), QueryFilterFields(plan.Filter)...)
	result := []string{}
	for _, name := range names {
		field, ok := lookup(name)
		if ok && field.Permission != "" && !slices.Contains(result, field.Permission) {
			result = append(result, field.Permission)
		}
	}
	return result
}
