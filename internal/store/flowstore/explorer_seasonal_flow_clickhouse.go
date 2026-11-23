// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/chclient"
)

func (c *ClickHouse) exploreSeasonalWindows(ctx context.Context, query PlanQuery, ends []time.Time, topKeys int) ([]PlanResult, error) {
	budget, err := explorerPlanBudget(ctx, c, query.TenantID, c)
	if err != nil {
		return nil, err
	}
	var vocabulary flow.QueryVocabulary
	if query.Tags != nil {
		vocabulary, err = query.Tags.Vocabulary(query.TenantID)
		if err != nil {
			return nil, err
		}
	}
	span, clocks, err := seasonalFlowPlan(ctx, query, ends, vocabulary, budget)
	if err != nil {
		return nil, err
	}
	external, err := planExternalProjections(ctx, query, span, budget.MemoryBytes/4)
	if err != nil {
		return nil, err
	}
	target, err := c.route(ctx, query.TenantID)
	if err != nil {
		return nil, err
	}
	lane, err := c.readLane(target, query.TenantID)
	if err != nil {
		return nil, err
	}
	if !lane.Reader {
		return nil, chclient.ErrReaderRequired
	}
	names, err := explorerInterfaceNames(ctx, c.explorerInterfaces, query.TenantID, span, budget)
	if err != nil {
		return nil, err
	}
	source, err := c.planSourceFor(ctx, target, lane, query.TenantID, span)
	if err != nil {
		return nil, err
	}
	for range 2 {
		result, err := makeSeasonalWindowResults(ctx, span, clocks, source, query, vocabulary)
		if err != nil {
			return nil, err
		}
		membershipLimit, err := seasonalMembershipAllowance(ctx, query.TenantID)
		if err != nil {
			return nil, err
		}
		read, err := buildSeasonalFlowSQL(ctx, budget, query, span, source.table, names, vocabulary, clocks, membershipLimit, topKeys)
		if err != nil {
			return nil, err
		}
		raw, err := c.explorerQueryRows(ctx, target, lane, query.TenantID, read.sql, read.params, append(external, read.clocks...)...)
		if err != nil {
			return nil, err
		}
		memberships, err := decodeSeasonalFlowRows(ctx, result, raw, membershipLimit, topKeys,
			usesDDoSWindowClock(query, clocks.lookback), query.DDoSVerifySampling, query.DDoSGroupSampledExporters)
		if err != nil {
			return nil, err
		}
		if err := chargeBatchRead(ctx, query.TenantID, memberships, 0); err != nil {
			return nil, err
		}
		current, err := c.planSourceFor(ctx, target, lane, query.TenantID, span)
		if err != nil {
			return nil, err
		}
		if current.kind == source.kind && current.coverage != nil && current.coverage.CompleteInputs {
			return result, ctx.Err()
		}
		source = current
	}
	return nil, &PlanCoverageError{Reason: "complete flow inputs advanced during the seasonal read", ResolutionSeconds: flow.MinPlanBucketSeconds}
}

func seasonalMembershipAllowance(ctx context.Context, tenant string) (int, error) {
	b, _ := ctx.Value(explorerBatchKey{}).(*PlanBatch)
	if b == nil || b.tenant != tenant {
		return 0, ErrNoTenant
	}
	b.costMu.Lock()
	defer b.costMu.Unlock()
	if b.readRows == 0 {
		return 0, ErrExplorerBudget
	}
	return b.readRows, ctx.Err()
}

func decodeSeasonalFlowRows(ctx context.Context, results []PlanResult, input []map[string]any, limit, topKeys int, clockEvidence, verifySampling, observeExporters bool) (int, error) {
	const invalid = "invalid seasonal flow response"
	memberships := 0
	previousPeriod := -1
	for _, raw := range input {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		period, err := strconv.Atoi(chToString(raw["clock_index"]))
		if err != nil || period < 0 || period < previousPeriod || period >= len(results) {
			return 0, errors.New(invalid)
		}
		previousPeriod = period
		repeat, err := strconv.Atoi(chToString(raw["membership"]))
		if err != nil || repeat < 1 || repeat > limit || (memberships != 0 && memberships != repeat) {
			return 0, errors.New(invalid)
		}
		memberships = repeat
		result := &results[period]
		if topKeys > 0 {
			population, err := strconv.Atoi(chToString(raw["total_groups"]))
			if err != nil || population < 1 || population > repeat ||
				result.TotalGroups != 0 && result.TotalGroups != population ||
				len(result.Rows) >= min(population, topKeys+1) {
				return 0, errors.New(invalid)
			}
			result.TotalGroups = population
		}
		clock := chParseTime(chToString(raw["oldest_input"]))
		if clock.IsZero() || clock.Before(result.Query.From) || !clock.Before(result.Query.To) {
			return 0, errors.New(invalid)
		}
		result.OldestInput = earliestPlanInput(result.OldestInput, clock)
		row, err := decodePlanGroup(raw["g"], result.Query.GroupBy, false)
		if err != nil {
			return 0, err
		}
		column, err := decodePlanGroup(raw["c"], result.Query.MatrixWith, false)
		if err != nil {
			return 0, err
		}
		metrics, err := decodePlanMetrics(result.Query, raw["metrics"])
		if err != nil {
			return 0, err
		}
		if result.Query.View == "matrix" {
			result.Matrix = append(result.Matrix, PlanMatrixCell{Row: row, Column: column, Metrics: metrics})
		} else {
			data := PlanRow{Group: row, Metrics: metrics}
			if clockEvidence {
				switch chToString(raw["crosses_window_start"]) {
				case "0":
				case "1":
					data.CrossesWindowStart = true
				default:
					return 0, errors.New(invalid)
				}
			}
			if verifySampling {
				switch chToString(raw["invalid_sampling_counters"]) {
				case "0":
				case "1":
					data.InvalidSamplingCounters = true
				default:
					return 0, errors.New(invalid)
				}
			}
			if observeExporters {
				data.DDoSUnsampledExporters, err = decodeDDoSUnsampledExporters(raw["ddos_unsampled_exporters"], row["sampling"] == "1")
				if err != nil {
					return 0, err
				}
			}
			result.Rows = append(result.Rows, data)
		}
	}
	if len(input) > memberships {
		return 0, errors.New(invalid)
	}
	if topKeys > 0 {
		for _, result := range results {
			if len(result.Rows) != min(result.TotalGroups, topKeys+1) {
				return 0, errors.New(invalid)
			}
		}
	}
	return memberships, ctx.Err()
}

func decodeDDoSUnsampledExporters(raw any, hasUnsampled bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || (len(values) != 0) != hasUnsampled {
		return nil, errors.New("invalid seasonal flow exporter observations")
	}
	if len(values) == 0 {
		return nil, nil
	}
	exporters := make([]string, len(values))
	for i, value := range values {
		exporter, ok := value.(string)
		if !ok {
			return nil, errors.New("invalid seasonal flow exporter observations")
		}
		exporters[i] = exporter
	}
	return exporters, nil
}
