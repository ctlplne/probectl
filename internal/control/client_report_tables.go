// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Projection consumes already-authorized, operation-local calculations. It
// neither queries sources nor grants artifact access. Freeze complete cells
// before rendering so input reuse or a renderer cannot mutate another table.
func projectClientReportSLIs(ctx context.Context, tenant string, from, to time.Time, availability []clientReportAvailability, objectives []clientReportSLO, memory int64) ([]reporting.CSVTable, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant {
		return nil, entity.ErrScopeMismatch
	}
	if from.IsZero() || !to.After(from) || memory <= 0 || int64(len(availability)) > memory/2048 || int64(len(objectives)) > memory/2048 {
		return nil, reportProjectionLimit()
	}
	p := &reportFlowProjection{ctx: ctx, tenant: tenant, memory: memory}
	if err := p.charge((int64(len(availability)) + int64(len(objectives))) * 1024); err != nil {
		return nil, err
	}
	availableRows := make([][]string, 0, len(availability))
	for _, item := range availability {
		if item.TenantID != tenant || !item.From.Equal(from) || !item.To.Equal(to) {
			return nil, entity.ErrScopeMismatch
		}
		source := item.Source
		row := []string{tenant, source.ContextID, source.EntityID, source.TestID, source.AgentID, source.Name, source.Type, source.DefinitionDigest, strconv.FormatInt(source.SourceGeneration, 10)}
		row = append(row, clientReportCountCells(item.Counts, item.OriginalCount, item.OriginalsDigest)...)
		if err := chargeClientReportCells(p, row); err != nil {
			return nil, err
		}
		availableRows = append(availableRows, row)
	}
	sloRows := make([][]string, 0, len(objectives))
	sloFrom := from
	for _, item := range objectives {
		if item.TenantID != tenant || item.From.IsZero() || !item.To.Equal(to) || !item.To.After(item.From) {
			return nil, entity.ErrScopeMismatch
		}
		// Reserve the full JSON worst case before serialization, including all
		// selected source identities. No shortened source list is substituted.
		if int64(len(item.Sources)) > p.memory/2048 {
			return nil, reportProjectionLimit()
		}
		for _, source := range item.Sources {
			if err := p.charge(2048); err != nil {
				return nil, err
			}
			for _, value := range []string{source.ContextID, source.EntityID, source.TestID, source.AgentID, source.Name, source.Type, source.DefinitionDigest} {
				if int64(len(value)) > p.memory/16 {
					return nil, reportProjectionLimit()
				}
				if err := p.charge(int64(len(value)) * 16); err != nil {
					return nil, err
				}
			}
		}
		sources, err := json.Marshal(item.Sources)
		if err != nil {
			return nil, err
		}
		meets := "unknown"
		if item.ObservedMeetsObjective != nil {
			meets = strconv.FormatBool(*item.ObservedMeetsObjective)
		}
		row := []string{tenant, item.Name, item.DisplayName, item.Service, item.DefinitionDigest, item.ObjectiveRatio, item.Basis, item.From.UTC().Format(time.RFC3339Nano), item.To.UTC().Format(time.RFC3339Nano), meets, string(sources)}
		row = append(row, clientReportCountCells(item.Counts, item.OriginalCount, item.OriginalsDigest)...)
		if err := chargeClientReportCells(p, row); err != nil {
			return nil, err
		}
		sloRows = append(sloRows, row)
		if item.From.Before(sloFrom) {
			sloFrom = item.From
		}
	}
	availableColumns := clientReportColumns([]string{"tenant_id", "context_id", "entity_id", "test_id", "agent_id", "test_name", "test_type", "definition_digest", "source_generation"})
	availableColumns[8].Numeric = true
	sloColumns := clientReportColumns([]string{"tenant_id", "slo_name", "display_name", "service", "definition_digest", "objective_ratio", "definition_basis", "window_from", "window_to", "observed_meets_objective", "selected_sources"})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []reporting.CSVTable{
		sealedClientReportTable(tenant, "client-availability", "Monthly availability", from, to, availableColumns, availableRows),
		sealedClientReportTable(tenant, "client-slos", "Configured SLO windows", sloFrom, to, sloColumns, sloRows),
	}, nil
}

func clientReportCountCells(counts clientReportOutcomeCounts, originals, digest string) []string {
	return []string{counts.Successful, counts.Failed, counts.Unknown, counts.Canceled, counts.AvailabilityNumerator, counts.AvailabilityDenominator, counts.Coverage, originals, digest}
}

func clientReportColumns(names []string) []reporting.CSVColumn {
	columns := make([]reporting.CSVColumn, 0, len(names)+9)
	for _, name := range names {
		columns = append(columns, reporting.CSVColumn{Name: name})
	}
	for index, name := range []string{"successful", "failed", "unknown", "canceled", "availability_numerator", "availability_denominator", "coverage", "original_count", "originals_digest"} {
		columns = append(columns, reporting.CSVColumn{Name: name, Numeric: index < 6 || index == 7})
	}
	return columns
}

func chargeClientReportCells(p *reportFlowProjection, row []string) error {
	for _, value := range row {
		if int64(len(value)) > p.memory/4 {
			return reportProjectionLimit()
		}
		if err := p.charge(64 + int64(len(value))*4); err != nil {
			return err
		}
	}
	return nil
}

func sealedClientReportTable(tenant, id, title string, from, to time.Time, columns []reporting.CSVColumn, rows [][]string) reporting.CSVTable {
	table := reporting.CSVTable{ID: id, Title: title, TenantID: tenant, Source: "configured-test original evidence and current definitions", AbsoluteFrom: from, AbsoluteTo: to, Columns: columns, ExpectedRows: int64(len(rows))}
	table.WalkRows = func(ctx context.Context, yield func([]string) error) error {
		bound, ok := tenancy.FromContext(ctx)
		if !ok || bound.String() != tenant {
			return entity.ErrScopeMismatch
		}
		if yield == nil {
			return entity.ErrInvalidClaim
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := yield(slices.Clone(row)); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	return table
}
