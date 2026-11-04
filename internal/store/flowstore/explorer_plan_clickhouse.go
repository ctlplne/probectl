// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/chclient"
)

// ExplorePlan executes the structured grammar through the policy-bound reader,
// and refuses unresolved references or resource overflows without partial data.
func (c *ClickHouse) ExplorePlan(ctx context.Context, query PlanQuery) (PlanResult, error) {
	if strings.TrimSpace(query.TenantID) == "" {
		return PlanResult{}, ErrNoTenant
	}
	budget, err := explorerPlanBudget(ctx, c, query.TenantID, c)
	if err != nil {
		return PlanResult{}, err
	}
	if err := budget.Validate(); err != nil {
		return PlanResult{}, err
	}
	ctx = withExplorerBudget(ctx, budget)
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	var vocabulary flow.QueryVocabulary
	var external []explorerExternalData
	if query.Tags != nil {
		vocabulary, err = query.Tags.Vocabulary(query.TenantID)
		if err != nil {
			return PlanResult{}, err
		}
	}
	plan, err := flow.NormalizeQueryPlanWithVocabulary(query.Plan, time.Now(), vocabulary)
	if err != nil {
		return PlanResult{}, err
	}
	if plan.Cursor != "" {
		return PlanResult{}, errors.New("flow cursor must be resolved from its stored snapshot before execution")
	}
	if query.Tags != nil {
		external, err = query.Tags.externalData(ctx, query.TenantID, plan, budget.MemoryBytes/4)
		if err != nil {
			return PlanResult{}, err
		}
	}

	target, err := c.route(ctx, query.TenantID)
	if err != nil {
		return PlanResult{}, err
	}
	lane, err := c.readLane(target, query.TenantID)
	if err != nil {
		return PlanResult{}, err
	}
	if !lane.Reader {
		return PlanResult{}, chclient.ErrReaderRequired
	}
	names, err := explorerInterfaceNames(ctx, c.explorerInterfaces, query.TenantID, plan, budget)
	if err != nil {
		return PlanResult{}, err
	}
	source, err := c.planSourceFor(ctx, target, lane, query.TenantID, plan)
	if err != nil {
		return PlanResult{}, err
	}
	sql, params, err := planSQLWithTags(budget, plan, source.table, names, query.TenantID,
		query.Tags, query.SelectedGroups, query.SelectedColumns, query.SelectedChartGroups, query.SelectedMatrixRows)
	if err != nil {
		return PlanResult{}, err
	}
	params["tenant"] = query.TenantID
	rows, err := c.explorerQueryRows(ctx, target, lane, query.TenantID, sql, params, external...)
	if err != nil {
		return PlanResult{}, err
	}
	result, err := decodePlanRows(plan, rows)
	if err != nil {
		return PlanResult{}, err
	}
	// Retention may advance while the raw query runs. Re-check before exposing
	// its answer, and retry from retained inputs within the original deadline.
	// An explicit raw override refuses rather than silently losing old rows.
	if source.kind == "raw" {
		current, err := c.planSourceFor(ctx, target, lane, query.TenantID, plan)
		if err != nil {
			return PlanResult{}, err
		}
		if current.kind != source.kind {
			sql, params, err := planSQLWithTags(budget, plan, current.table, names, query.TenantID,
				query.Tags, query.SelectedGroups, query.SelectedColumns, query.SelectedChartGroups, query.SelectedMatrixRows)
			if err != nil {
				return PlanResult{}, err
			}
			params["tenant"] = query.TenantID
			rows, err := c.explorerQueryRows(ctx, target, lane, query.TenantID, sql, params, external...)
			if err != nil {
				return PlanResult{}, err
			}
			result, err = decodePlanRows(plan, rows)
			if err != nil {
				return PlanResult{}, err
			}
			source = current
		}
	}
	result.Source = source.kind
	result.Coverage = source.coverage
	if query.Tags != nil {
		fields, err := vocabulary.Fields()
		if err != nil {
			return PlanResult{}, err
		}
		for _, field := range fields {
			if field.Derived == "tenant_tag" {
				result.Coverage.Fields = append(result.Coverage.Fields, field.Name)
			}
		}
	}
	if err := captureResultTagIdentity(&result, query, vocabulary); err != nil {
		return PlanResult{}, err
	}
	if source.coverage != nil {
		result.ResolutionSeconds = source.coverage.ResolutionSeconds
	}
	if query.SelectedGroups != nil {
		selected, err := normalizePlanGroupsWithVocabulary(query.SelectedGroups, plan, vocabulary)
		if err != nil {
			return PlanResult{}, err
		}
		ranks := map[string]int{}
		for i, tuple := range selected {
			encoded, _ := json.Marshal(tuple)
			ranks[string(encoded)] = i
		}
		key := func(row PlanRow) string {
			tuple := make([]string, len(plan.GroupBy))
			for i, field := range plan.GroupBy {
				tuple[i] = row.Group[field]
			}
			encoded, _ := json.Marshal(tuple)
			return string(encoded)
		}
		sort.Slice(result.Rows, func(i, j int) bool { return ranks[key(result.Rows[i])] < ranks[key(result.Rows[j])] })
	}
	if query.SelectedColumns != nil {
		selected, err := normalizePlanColumnsWithVocabulary(query.SelectedColumns, plan, vocabulary)
		if err != nil {
			return PlanResult{}, err
		}
		ranks := map[string]int{}
		for i, tuple := range selected {
			encoded, _ := json.Marshal(tuple)
			ranks[string(encoded)] = i
		}
		key := func(row PlanRow) string {
			tuple := make([]string, len(plan.MatrixWith))
			for i, name := range plan.MatrixWith {
				tuple[i] = row.Group[name]
			}
			encoded, _ := json.Marshal(tuple)
			return string(encoded)
		}
		sort.Slice(result.MatrixColumns, func(i, j int) bool { return ranks[key(result.MatrixColumns[i])] < ranks[key(result.MatrixColumns[j])] })
	}
	for _, selection := range []struct {
		rows     []PlanRow
		fields   []string
		selected [][]string
	}{{result.ChartRows, plan.GroupBy, query.SelectedChartGroups}, {result.MatrixRows, plan.GroupBy, query.SelectedMatrixRows}} {
		if selection.selected == nil {
			continue
		}
		ranks := map[string]int{}
		for i, tuple := range selection.selected {
			encoded, _ := json.Marshal(tuple)
			ranks[string(encoded)] = i
		}
		key := func(row PlanRow) string {
			tuple := make([]string, len(selection.fields))
			for i, name := range selection.fields {
				tuple[i] = row.Group[name]
			}
			encoded, _ := json.Marshal(tuple)
			return string(encoded)
		}
		sort.Slice(selection.rows, func(i, j int) bool { return ranks[key(selection.rows[i])] < ranks[key(selection.rows[j])] })
	}
	if err := ctx.Err(); err != nil {
		return PlanResult{}, err
	}
	return result, nil
}

func decodePlanRows(plan flow.QueryPlan, input []map[string]any) (PlanResult, error) {
	result := PlanResult{Query: plan, Source: "raw", Rows: []PlanRow{}, Series: []PlanPoint{}, OtherSeries: []PlanPoint{}, TotalSeries: []PlanPoint{}, Matrix: []PlanMatrixCell{}, Totals: map[string]string{}}
	for _, metric := range plan.Metrics {
		result.Totals[planMetricKey(metric)] = "0"
	}
	if len(input) > planIntermediateLimit {
		return PlanResult{}, ErrExplorerBudget
	}

	countsSeen := false
	totalBuckets := map[int64]bool{}
	var metadataCount int
	for _, raw := range input {
		metrics, err := decodePlanMetrics(plan, raw["metrics"])
		if err != nil {
			return PlanResult{}, err
		}
		other, columnOther := chToUint64(raw["o"]) == 1, chToUint64(raw["p"]) == 1
		switch chToString(raw["kind"]) {
		case "counts":
			if countsSeen {
				return PlanResult{}, errors.New("duplicate flow count metadata")
			}
			count, oldest, err := decodePlanCountMetadata(plan, raw)
			if err != nil {
				return PlanResult{}, err
			}
			countsSeen, metadataCount, result.OldestInput = true, count, oldest

		case "detail":
			g, err := decodePlanGroup(raw["g"], plan.GroupBy, false)
			if err != nil {
				return PlanResult{}, err
			}
			count := chToUint64(raw["total_groups"])
			if count > planIntermediateLimit {
				return PlanResult{}, ErrExplorerBudget
			}
			if result.TotalGroups != 0 && result.TotalGroups != int(count) {
				return PlanResult{}, errors.New("inconsistent flow grouping count")
			}
			result.TotalGroups = int(count)
			result.Rows = append(result.Rows, PlanRow{Group: g, Metrics: metrics})
		case "chart_detail", "matrix_row":
			g, err := decodePlanGroup(raw["g"], plan.GroupBy, false)
			if err != nil || other {
				return PlanResult{}, errors.New("invalid global flow grouping response")
			}
			row := PlanRow{Group: g, Metrics: metrics}
			if chToString(raw["kind"]) == "chart_detail" {
				if plan.View == "table" || plan.View == "matrix" || len(result.ChartRows) >= plan.SeriesDepth {
					return PlanResult{}, errors.New("invalid global chart population")
				}
				result.ChartRows = append(result.ChartRows, row)
			} else {
				if plan.View != "matrix" || len(result.MatrixRows) >= plan.MatrixDepth {
					return PlanResult{}, errors.New("invalid matrix row population")
				}
				result.MatrixRows = append(result.MatrixRows, row)
			}
		case "other":
			if result.Other != nil || !other {
				return PlanResult{}, errors.New("invalid Other response")
			}
			result.Other = &PlanRow{Group: map[string]string{}, Other: true, Metrics: metrics}
		case "chart_other":
			if result.ChartOther != nil || !other || plan.View == "table" || plan.View == "matrix" {
				return PlanResult{}, errors.New("invalid chart Other response")
			}
			result.ChartOther = &PlanRow{Group: map[string]string{}, Other: true, Metrics: metrics}
		case "totals":
			result.Totals = metrics
		case "matrix_column":
			g, err := decodePlanGroup(raw["g"], plan.MatrixWith, false)
			if err != nil || plan.View != "matrix" || len(result.MatrixColumns) >= plan.MatrixDepth {
				return PlanResult{}, errors.New("invalid flow matrix column response")
			}
			result.MatrixColumns = append(result.MatrixColumns, PlanRow{Group: g, Metrics: metrics})
		case "point", "total_point":
			if err := appendDecodedPlanPoint(plan, raw, metrics, &result, totalBuckets); err != nil {
				return PlanResult{}, err
			}
		case "matrix":
			g, err := decodePlanGroup(raw["g"], plan.GroupBy, other)
			if err != nil {
				return PlanResult{}, err
			}
			column, err := decodePlanGroup(raw["c"], plan.MatrixWith, columnOther)
			if err != nil {
				return PlanResult{}, err
			}
			result.Matrix = append(result.Matrix, PlanMatrixCell{Row: g, Column: column, RowOther: other, ColumnOther: columnOther, Metrics: metrics})
		default:
			return PlanResult{}, errors.New("invalid flow response kind")
		}
	}
	if !countsSeen || (result.TotalGroups != 0 && result.TotalGroups != metadataCount) {
		return PlanResult{}, errors.New("missing or inconsistent flow count metadata")
	}
	result.TotalGroups = metadataCount
	if result.TotalGroups == 0 && len(result.TotalSeries) != 0 {
		return PlanResult{}, errors.New("total flow buckets without matching input")
	}
	if len(result.Rows) > plan.RowLimit {
		return PlanResult{}, ErrExplorerBudget
	}
	result.DetailLimited = result.Other != nil || result.TotalGroups > plan.RowLimit
	sortDecodedPlanResult(plan, &result)
	return result, nil
}

func decodePlanCountMetadata(plan flow.QueryPlan, raw map[string]any) (int, time.Time, error) {
	count := chToUint64(raw["total_groups"])
	if count > planIntermediateLimit {
		return 0, time.Time{}, ErrExplorerBudget
	}
	var oldestInput time.Time
	oldest := chToString(raw["oldest_input"])
	if oldest != "" {
		oldestInput = chParseTime(oldest)
		if oldestInput.IsZero() || oldestInput.Before(plan.From) || !oldestInput.Before(plan.To) || count == 0 {
			return 0, time.Time{}, errors.New("invalid flow input-retention metadata")
		}
	} else if count != 0 {
		return 0, time.Time{}, errors.New("missing flow input-retention metadata")
	}
	return int(count), oldestInput, nil
}

func decodePlanGroup(raw any, fields []string, other bool) (map[string]string, error) {
	tuple, ok := raw.([]any)
	if !ok {
		return nil, errors.New("invalid flow grouping response")
	}
	out := map[string]string{}
	if other {
		if len(tuple) != 0 {
			return nil, errors.New("invalid structural Other grouping")
		}
		return out, nil
	}
	if len(tuple) != len(fields) {
		return nil, errors.New("invalid flow grouping width")
	}
	for i, name := range fields {
		value, ok := tuple[i].(string)
		if !ok {
			return nil, errors.New("invalid flow grouping value")
		}
		field, _ := flow.LookupQueryField(name)
		if field.Type == flow.QueryTimestamp {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return nil, errors.New("invalid flow grouping timestamp")
			}
			value = parsed.UTC().Format(time.RFC3339Nano)
		}
		out[name] = value
	}
	return out, nil
}

func decodePlanMetrics(plan flow.QueryPlan, raw any) (map[string]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) != len(plan.Metrics) {
		return nil, errors.New("invalid flow metric response width")
	}
	metrics := map[string]string{}
	for i, metric := range plan.Metrics {
		value, ok := values[i].(string)
		if !ok || len(value) > 256 {
			return nil, errors.New("invalid flow metric response")
		}
		number, ok := new(big.Rat).SetString(value)
		if !ok || number.Sign() < 0 {
			return nil, errors.New("invalid flow metric response")
		}
		metrics[planMetricKey(metric)] = planMetricString(number)
	}
	return metrics, nil
}

func appendDecodedPlanPoint(plan flow.QueryPlan, raw map[string]any, metrics map[string]string, result *PlanResult, totalBuckets map[int64]bool) error {
	other := chToUint64(raw["o"]) == 1
	isTotal := chToString(raw["kind"]) == "total_point"
	if plan.View == "table" || (!isTotal && plan.View == "matrix") {
		return errors.New("unexpected flow bucket for view")
	}
	fields := plan.GroupBy
	if isTotal {
		fields = nil
		if !planZeroFlag(raw["o"]) || !planZeroFlag(raw["p"]) {
			return errors.New("invalid total flow bucket flags")
		}
		if _, err := decodePlanGroup(raw["c"], nil, false); err != nil {
			return err
		}
	}
	g, err := decodePlanGroup(raw["g"], fields, other)
	if err != nil {
		return err
	}
	index, err := strconv.ParseInt(chToString(raw["bi"]), 10, 64)
	if err != nil || index < 0 {
		return errors.New("invalid flow bucket")
	}
	width := time.Duration(plan.BucketSeconds) * time.Second
	if index > int64((plan.To.Sub(plan.From)-1)/width) {
		return errors.New("flow bucket outside query range")
	}
	start, duration := planBucketBounds(plan, index)
	actual, err := strconv.ParseInt(chToString(raw["duration"]), 10, 64)
	if err != nil || actual != int64(duration) {
		return errors.New("invalid flow bucket duration")
	}
	for _, metric := range plan.Metrics {
		if metric.Role == "additional" {
			delete(metrics, planMetricKey(metric))
		}
	}
	point := PlanPoint{Group: g, Other: other, TS: start, DurationSeconds: new(big.Rat).SetFrac(big.NewInt(int64(duration)), big.NewInt(int64(time.Second))).FloatString(9), Metrics: metrics}
	switch {
	case isTotal:
		if totalBuckets[index] {
			return errors.New("duplicate total flow bucket")
		}
		totalBuckets[index] = true
		result.TotalSeries = append(result.TotalSeries, point)
	case other:
		result.OtherSeries = append(result.OtherSeries, point)
	default:
		result.Series = append(result.Series, point)
	}
	return nil
}

func sortDecodedPlanResult(plan flow.QueryPlan, result *PlanResult) {
	primary := planPrimary(plan)
	tupleKey := func(group map[string]string, fields []string) string {
		tuple := make([]string, len(fields))
		for i, field := range fields {
			tuple[i] = group[field]
		}
		encoded, _ := json.Marshal(tuple)
		return string(encoded)
	}
	sortRows := func(rows []PlanRow, fields []string) {
		sort.Slice(rows, func(i, j int) bool {
			a, _ := new(big.Rat).SetString(rows[i].Metrics[primary])
			b, _ := new(big.Rat).SetString(rows[j].Metrics[primary])
			if cmp := a.Cmp(b); cmp != 0 {
				return cmp > 0
			}
			return tupleKey(rows[i].Group, fields) < tupleKey(rows[j].Group, fields)
		})
	}
	sortRows(result.Rows, plan.GroupBy)
	sortRows(result.ChartRows, plan.GroupBy)
	sortRows(result.MatrixRows, plan.GroupBy)
	sortRows(result.MatrixColumns, plan.MatrixWith)
	sortPlanPoints(result.Series)
	sortPlanPoints(result.OtherSeries)
	sortPlanPoints(result.TotalSeries)
	matrixKey := func(cell PlanMatrixCell) string {
		row, column := "", ""
		if !cell.RowOther {
			row = tupleKey(cell.Row, plan.GroupBy)
		}
		if !cell.ColumnOther {
			column = tupleKey(cell.Column, plan.MatrixWith)
		}
		encoded, _ := json.Marshal([]any{row, column, cell.RowOther, cell.ColumnOther})
		return string(encoded)
	}
	sort.Slice(result.Matrix, func(i, j int) bool { return matrixKey(result.Matrix[i]) < matrixKey(result.Matrix[j]) })
}

// The ClickHouse JSON reader preserves UInt8 flags as json.Number. Accept
// only an exact zero (or its quoted representation), never a failed numeric
// coercion that silently turns malformed data into a total bucket.
func planZeroFlag(value any) bool {
	switch number := value.(type) {
	case json.Number:
		return number.String() == "0"
	case string:
		return number == "0"
	default:
		return false
	}
}

var _ PlanStore = (*ClickHouse)(nil)
