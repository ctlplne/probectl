// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/csv"
	"regexp"
	"strings"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

var flowCSVSignedDecimal = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]{1,18})?$`)

type flowComparisonCSVFormat struct {
	flowCSVFormat
	budget flowstore.ExplorerBudget
}

func newFlowComparisonCSVFormat(plan flow.QueryPlan, budgets ...flowstore.ExplorerBudget) (flowComparisonCSVFormat, []string, error) {
	budget, err := flowComparisonCostBudget(budgets)
	if err != nil {
		return flowComparisonCSVFormat{}, nil, err
	}
	format, _, err := newFlowCSVFormat(plan)
	if err != nil {
		return flowComparisonCSVFormat{}, nil, err
	}
	columns := []string{"record_type"}
	for _, group := range format.groups {
		columns = append(columns, flowCSVText(group))
	}
	columns = append(columns, "measure", "calculation", "current", "previous", "delta", "percent_change", "delta_state")
	return flowComparisonCSVFormat{flowCSVFormat: format, budget: budget}, columns, nil
}

func (f flowComparisonCSVFormat) write(writer *csv.Writer, now, before *flowstore.PlanRow, kind string) error {
	var current, previous []flowstore.PlanRow
	if now != nil {
		current = []flowstore.PlanRow{*now}
	}
	if before != nil {
		previous = []flowstore.PlanRow{*before}
	}
	if now == nil && before == nil {
		return flowsnapshot.ErrIntegrity
	}
	for _, row := range append(current, previous...) {
		if kind == "detail" || kind == "other" {
			if _, err := f.row(row, kind); err != nil {
				return err
			}
		} else if kind != "totals" || row.Other {
			return flowsnapshot.ErrIntegrity
		}
	}
	aligned, err := alignExactFlowComparison(current, previous, f.groups, f.metrics, 1, f.budget)
	if err != nil {
		return err
	}
	for _, row := range aligned {
		record := make([]string, 1+len(f.groups))
		record[0] = kind
		if kind == "detail" {
			for i, group := range f.groups {
				record[i+1] = flowCSVText(row.Group[group])
			}
		}
		measure, calculation, _ := strings.Cut(row.Measure, ":")
		record = append(record, flowCSVText(measure), flowCSVText(calculation))
		for i, value := range []*string{row.CurrentExact, row.PreviousExact, row.DeltaExact, row.PercentExact} {
			text := ""
			if value != nil {
				text = *value
				valid := flowCSVDecimal.MatchString(text)
				if i >= 2 {
					valid = flowCSVSignedDecimal.MatchString(text)
				}
				if len(text) > 256 || !valid {
					return flowsnapshot.ErrIntegrity
				}
			}
			record = append(record, text)
		}
		record = append(record, row.DeltaState)
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	return nil
}
