// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
)

type seasonalMemoryGroup struct {
	aggregate *planAggregate
	column    map[string]string
}

type seasonalMemoryKey struct {
	row, column             string
	crossesWindowStart      bool
	invalidSamplingCounters bool
}

type seasonalMemoryPeriod map[seasonalMemoryKey]seasonalMemoryGroup

func (m *Memory) exploreSeasonalWindows(ctx context.Context, query PlanQuery, ends []time.Time, topKeys int) ([]PlanResult, error) {
	budget, err := explorerPlanBudget(ctx, m, query.TenantID, m)
	if err != nil {
		return nil, err
	}
	vocabulary, err := memoryPlanTagVocabulary(query)
	if err != nil {
		return nil, err
	}
	span, clocks, err := seasonalFlowPlan(ctx, query, ends, vocabulary, budget)
	if err != nil {
		return nil, err
	}
	if span.DataSeries == "rollup" {
		return nil, errors.New("rollup coverage is unavailable from the memory store")
	}
	prepared, err := flow.PrepareQueryFilterWithVocabulary(span.Filter, vocabulary)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	source := m.explorerInterfaces
	m.mu.Unlock()
	names, err := explorerInterfaceNames(ctx, source, query.TenantID, span, budget)
	if err != nil {
		return nil, err
	}
	snapshotBudget := budget
	snapshotBudget.MemoryBytes /= 2
	entries, err := m.explorerSnapshot(withExplorerBudget(ctx, snapshotBudget), query.TenantID, span)
	if err != nil {
		return nil, err
	}
	sourceCoverage := planSource{kind: "raw", coverage: &PlanSourceCoverage{Fields: allPlanFields(), ResolutionSeconds: flow.MinPlanBucketSeconds, CompleteInputs: true}}
	results, err := makeSeasonalWindowResults(ctx, span, clocks, sourceCoverage, query, vocabulary)
	if err != nil {
		return nil, err
	}
	distinct := planDistinctFields(span)
	cost := &planCost{budget: snapshotBudget}
	periods := make([]seasonalMemoryPeriod, len(results))
	clockEvidence := usesDDoSWindowClock(query, clocks.lookback)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		first, after := clocks.indices(entry.row.TS)
		if first == after {
			continue
		}
		values := map[string]string{}
		value := func(field string) string {
			if found, ok := values[field]; ok {
				return found
			}
			var got string
			if _, routing := flow.RoutingQueryField(field); routing {
				got = query.Routing.valueForRow(entry.row, field)
			} else {
				got = explorerFieldValue(entry, field, span, names, vocabulary, query.Tags, query.Roles)
			}
			values[field] = got
			return got
		}
		if !prepared.Matches(value) {
			continue
		}
		if err := chargeBatchRead(ctx, query.TenantID, after-first, 0); err != nil {
			return nil, err
		}
		groupValue := value
		if query.DDoSProjection && value("transport") != "udp" {
			groupValue = func(field string) string {
				if field == "src_port" {
					return "0"
				}
				return value(field)
			}
		}
		rowKey, row := planTuple(groupValue, span.GroupBy)
		colKey, column := planTuple(value, span.MatrixWith)
		invalidCounters := query.DDoSVerifySampling && seasonalSamplingCountersInvalid(entry.row)
		for i := first; i < after; i++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			key := seasonalMemoryKey{row: rowKey, column: colKey, invalidSamplingCounters: invalidCounters, crossesWindowStart: clockEvidence &&
				entry.row.ClockBasis == flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL &&
				!entry.row.StartTS.IsZero() && entry.row.StartTS.Before(results[i].Query.From)}
			group, found := periods[i][key]
			if !found {
				if err := cost.charge(1, 640+len(rowKey)+len(colKey)); err != nil {
					return nil, err
				}
				if periods[i] == nil {
					periods[i] = make(seasonalMemoryPeriod)
				}
				group = seasonalMemoryGroup{aggregate: newPlanAggregate(row, distinct), column: column}
				periods[i][key] = group
			}
			if err := group.aggregate.add(entry.row, results[i].Query, distinct, cost); err != nil {
				return nil, err
			}
			results[i].OldestInput = earliestPlanInput(results[i].OldestInput, entry.row.TS)
		}
	}
	response := budget.ResponseBytes
	for i := range results {
		if err := renderSeasonalMemoryPeriod(ctx, &results[i], periods[i], &response, topKeys); err != nil {
			return nil, err
		}
	}
	return results, ctx.Err()
}

func seasonalSamplingCountersInvalid(row Row) bool {
	if row.Sampling == 0 {
		return true
	}
	maximum := math.MaxUint64 / row.Sampling
	return row.Bytes > maximum || row.Packets > maximum ||
		row.Bytes*row.Sampling != row.BytesScaled || row.Packets*row.Sampling != row.PacketsScaled
}

func renderSeasonalMemoryPeriod(ctx context.Context, result *PlanResult, groups seasonalMemoryPeriod, remaining *int64, topKeys int) error {
	keys := make([]seasonalMemoryKey, 0, len(groups))
	primary := planPrimary(result.Query)
	if topKeys > 0 && primary == "" {
		return ErrExplorerBudget
	}
	for key, group := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		if topKeys > 0 {
			if err := group.aggregate.calculate(result.Query); err != nil {
				return err
			}
		}
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b seasonalMemoryKey) int {
		if topKeys > 0 {
			if order := groups[b].aggregate.stats[primary].Cmp(groups[a].aggregate.stats[primary]); order != 0 {
				return order
			}
		}
		if compare := strings.Compare(a.row, b.row); compare != 0 {
			return compare
		}
		if compare := strings.Compare(a.column, b.column); compare != 0 {
			return compare
		}
		if a.crossesWindowStart != b.crossesWindowStart {
			if a.crossesWindowStart {
				return 1
			}
			return -1
		}
		if a.invalidSamplingCounters != b.invalidSamplingCounters {
			if a.invalidSamplingCounters {
				return 1
			}
			return -1
		}
		return 0
	})
	if topKeys > 0 {
		result.TotalGroups = len(keys)
		keys = keys[:min(len(keys), topKeys+1)]
	}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		group := groups[key]
		if topKeys == 0 {
			if err := group.aggregate.calculate(result.Query); err != nil {
				return err
			}
		}
		row := group.aggregate.row(false)
		row.CrossesWindowStart = key.crossesWindowStart
		row.InvalidSamplingCounters = key.invalidSamplingCounters
		bytes := int64(128 + len(key.row) + len(key.column))
		for name, value := range row.Metrics {
			bytes += int64(16 + len(name) + len(value))
		}
		if bytes > *remaining {
			return ErrExplorerBudget
		}
		*remaining -= bytes
		if result.Query.View == "matrix" {
			result.Matrix = append(result.Matrix, PlanMatrixCell{Row: row.Group, Column: group.column, Metrics: row.Metrics})
		} else {
			result.Rows = append(result.Rows, row)
		}
	}
	return ctx.Err()
}
