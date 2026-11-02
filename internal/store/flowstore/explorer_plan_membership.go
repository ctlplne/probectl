// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"encoding/json"
	"errors"

	"github.com/ctlplne/probectl/internal/flow"
)

// normalizePlanGroups validates internal membership without granting access.
// The policy-bound tenant read remains the outermost scope. Group values are
// bound data, including labels that look like SQL and unassigned empty values.
func normalizePlanGroups(input [][]string, plan flow.QueryPlan, budgets ...ExplorerBudget) ([][]string, error) {
	return normalizePlanGroupsWithVocabulary(input, plan, flow.QueryVocabulary{}, budgets...)
}

func normalizePlanGroupsWithVocabulary(input [][]string, plan flow.QueryPlan,
	vocabulary flow.QueryVocabulary, budgets ...ExplorerBudget) ([][]string, error) {
	return normalizePlanMembershipWithVocabulary(input, plan.GroupBy, plan.RowLimit, vocabulary, budgets...)
}

func normalizePlanColumns(input [][]string, plan flow.QueryPlan, budgets ...ExplorerBudget) ([][]string, error) {
	return normalizePlanColumnsWithVocabulary(input, plan, flow.QueryVocabulary{}, budgets...)
}

func normalizePlanColumnsWithVocabulary(input [][]string, plan flow.QueryPlan,
	vocabulary flow.QueryVocabulary, budgets ...ExplorerBudget) ([][]string, error) {
	if input != nil && plan.View != "matrix" {
		return nil, errors.New("column membership requires a matrix")
	}
	return normalizePlanMembershipWithVocabulary(input, plan.MatrixWith, plan.MatrixDepth, vocabulary, budgets...)
}

func normalizePlanMatrixRows(input [][]string, plan flow.QueryPlan, budgets ...ExplorerBudget) ([][]string, error) {
	return normalizePlanMatrixRowsWithVocabulary(input, plan, flow.QueryVocabulary{}, budgets...)
}

func normalizePlanMatrixRowsWithVocabulary(input [][]string, plan flow.QueryPlan,
	vocabulary flow.QueryVocabulary, budgets ...ExplorerBudget) ([][]string, error) {
	if input != nil && plan.View != "matrix" {
		return nil, errors.New("matrix row membership requires a matrix")
	}
	return normalizePlanMembershipWithVocabulary(input, plan.GroupBy, plan.MatrixDepth, vocabulary, budgets...)
}

func normalizePlanChartGroups(input [][]string, plan flow.QueryPlan, budgets ...ExplorerBudget) ([][]string, error) {
	return normalizePlanChartGroupsWithVocabulary(input, plan, flow.QueryVocabulary{}, budgets...)
}

func normalizePlanChartGroupsWithVocabulary(input [][]string, plan flow.QueryPlan,
	vocabulary flow.QueryVocabulary, budgets ...ExplorerBudget) ([][]string, error) {
	if input != nil && (plan.View == "table" || plan.View == "matrix") {
		return nil, errors.New("chart membership requires a chart view")
	}
	return normalizePlanMembershipWithVocabulary(input, plan.GroupBy, plan.SeriesDepth, vocabulary, budgets...)
}

func normalizePlanMembership(input [][]string, fields []string, limit int, budgets ...ExplorerBudget) ([][]string, error) {
	return normalizePlanMembershipWithVocabulary(input, fields, limit, flow.QueryVocabulary{}, budgets...)
}

func normalizePlanMembershipWithVocabulary(input [][]string, fields []string, limit int,
	vocabulary flow.QueryVocabulary, budgets ...ExplorerBudget) ([][]string, error) {
	budget, err := selectExplorerBudget(budgets)
	if err != nil {
		return nil, err
	}
	if input == nil {
		return nil, nil
	}
	if len(input) > limit {
		return nil, ErrExplorerBudget
	}
	result := make([][]string, 0, len(input))
	seen := map[string]bool{}
	size := 0
	for _, tuple := range input {
		if len(tuple) != len(fields) {
			return nil, errors.New("invalid comparison grouping width")
		}
		group := make([]string, len(tuple))
		for i, value := range tuple {
			field, ok := vocabulary.Lookup(fields[i])
			if !ok {
				return nil, errors.New("invalid comparison field")
			}
			size += len(value) + 16
			if int64(size) > min(budget.ReadBytes, budget.MemoryBytes) {
				return nil, ErrExplorerBudget
			}
			if field.Type == flow.QueryText {
				if len(value) > flow.MaxQueryValueBytes {
					return nil, ErrExplorerBudget
				}
				group[i] = value
				continue
			}
			normalized, err := flow.NormalizeQueryPredicatesWithVocabulary([]flow.QueryPredicate{{Field: field.Name, Op: flow.QueryEqual, Values: []string{value}}}, vocabulary)
			if err != nil {
				return nil, err
			}
			group[i] = normalized[0].Values[0]
		}
		encoded, _ := json.Marshal(group)
		key := string(encoded)
		if seen[key] {
			return nil, errors.New("duplicate comparison group")
		}
		seen[key] = true
		result = append(result, group)
	}
	return result, nil
}
