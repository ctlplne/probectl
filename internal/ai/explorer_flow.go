// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

// IsRecordFlowQuery distinguishes the registry grammar from retained interface
// capacity recipes. Old saved views keep their original site/interface meaning.
func IsRecordFlowQuery(q ExplorerQuery) bool {
	if q.Source != ExplorerFlow {
		return false
	}
	if q.Flow != nil {
		return true
	}
	for _, fields := range [][]string{q.Dimensions, q.Groupings} {
		for _, field := range fields {
			if !contains([]string{"site", "interface", "direction"}, strings.ToLower(strings.TrimSpace(field))) {
				return true
			}
		}
	}
	for _, measure := range q.Measures {
		if !contains([]string{"bps", "pps"}, strings.ToLower(strings.TrimSpace(measure))) {
			return true
		}
	}
	for field := range q.Filters {
		if !contains([]string{"site", "interface", "direction"}, strings.ToLower(strings.TrimSpace(field))) {
			return true
		}
	}
	return false
}

// ExplorerFlowSpec maps the public envelope to the same spec the store validates.
// This is also used by MCP; there is no second field/operator vocabulary.
func ExplorerFlowSpec(q ExplorerQuery, now time.Time) (flow.QueryPlan, error) {
	if q.Source != ExplorerFlow {
		return flow.QueryPlan{}, errors.New("flow query requires the flow source")
	}
	plan := flow.QueryPlan{}
	if q.Flow != nil {
		plan = *q.Flow
	}
	if !q.From.IsZero() {
		plan.From = q.From
	}
	if !q.To.IsZero() {
		plan.To = q.To
	}
	groups := q.Groupings
	if len(groups) == 0 {
		groups = q.Dimensions
	}
	if len(q.Dimensions) > 0 && len(q.Groupings) > 0 {
		dims := append([]string{}, q.Dimensions...)
		keys := append([]string{}, q.Groupings...)
		for i := range dims {
			dims[i] = strings.ToLower(strings.TrimSpace(dims[i]))
		}
		for i := range keys {
			keys[i] = strings.ToLower(strings.TrimSpace(keys[i]))
		}
		sort.Strings(dims)
		sort.Strings(keys)
		if !slices.Equal(dims, keys) {
			return flow.QueryPlan{}, errors.New("flow dimensions must match the grouping fields")
		}
	}
	if len(groups) > 0 {
		plan.GroupBy = groups
	}
	if len(plan.Metrics) == 0 && len(q.Measures) > 0 {
		for i, name := range q.Measures {
			measure, calculation, found := strings.Cut(strings.ToLower(strings.TrimSpace(name)), ":")
			if !found {
				calculation = "total"
				if measure == "bps" || measure == "pps" || measure == "fps" {
					calculation = "avg"
				}
			}
			role := "additional"
			if i == 0 {
				role = "primary"
			}
			plan.Metrics = append(plan.Metrics, flow.QueryMetric{Measure: measure, Calculation: calculation, Role: role})
		}
	}
	if q.Visualization != "" {
		plan.View = q.Visualization
	}
	if q.Limit != 0 {
		if plan.RowLimit != 0 && plan.RowLimit != q.Limit {
			return flow.QueryPlan{}, errors.New("flow row limit conflicts with the query envelope")
		}
		plan.RowLimit = q.Limit
	}
	conditions := []flow.QueryPredicate{}
	keys := make([]string, 0, len(q.Filters))
	for key := range q.Filters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if isTenantSelector(strings.ToLower(strings.TrimSpace(key))) {
			return flow.QueryPlan{}, errors.New("tenant scope comes from authentication and cannot be filtered")
		}
		conditions = append(conditions, flow.QueryPredicate{Field: key, Op: flow.QueryEqual, Values: []string{q.Filters[key]}})
	}
	if len(conditions) > 0 {
		legacy := flow.QueryFilterGroup{Conditions: conditions}
		if plan.Filter == nil {
			plan.Filter = &legacy
		} else {
			plan.Filter = &flow.QueryFilterGroup{Match: "all", Groups: []flow.QueryFilterGroup{*plan.Filter, legacy}}
		}
	}
	return flow.NormalizeQueryPlan(plan, now)
}
