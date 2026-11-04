// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// capturedReportFlow is an already-authorized, request-owned query result.
// Projection grants no source access and does not adopt a private cache handle.
// The capture boundary supplies the authenticated tenant, exact view version
// and the actual successful metadata capture time, never a client claim.
type capturedReportFlow struct {
	TenantID, ID, Version, Name, Period string
	TagAsOf                             time.Time
	Result                              flowstore.PlanResult
}

type reportFlowProjection struct {
	ctx          context.Context
	tenant       string
	memory, rows int64
	tables       []reporting.CSVTable
	identities   map[string]bool
}

// These limits cover the complete projection batch, independently of the
// source query and renderer/staging budgets. No section or row is truncated.
func projectReportFlowRecords(ctx context.Context, captures []capturedReportFlow, memory, rows int64) ([]reporting.CSVTable, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() == "" {
		return nil, apierror.Forbidden("report source tenant scope is unavailable")
	}
	if memory <= 0 || rows <= 0 {
		return nil, reportProjectionLimit()
	}
	projection := &reportFlowProjection{ctx: ctx, tenant: tenant.String(), memory: memory, rows: rows, identities: make(map[string]bool)}
	for _, capture := range captures {
		if err := projection.add(capture); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return projection.tables, nil
}

func reportProjectionLimit() error {
	return apierror.Validation("report source projection budget exceeded")
}

func (p *reportFlowProjection) charge(n int64) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if n < 0 || n > p.memory {
		return reportProjectionLimit()
	}
	p.memory -= n
	return nil
}

func (p *reportFlowProjection) add(c capturedReportFlow) error {
	if err := p.validate(c); err != nil {
		return err
	}
	r := c.Result
	if len(r.TagIDs) > 0 {
		names := make([]string, 0, len(r.TagIDs))
		for name := range r.TagIDs {
			names = append(names, name)
		}
		sort.Strings(names)
		if err := p.table(c, "field_identities", []reporting.CSVColumn{{Name: "query_field"}, {Name: "definition_id"}}, nil, len(names), func(i int) ([]string, error) { return []string{names[i], r.TagIDs[names[i]]}, nil }); err != nil {
			return err
		}
	}
	if err := p.groups(c, "detail", r.Query.GroupBy, r.Rows, r.Other, r.Totals); err != nil {
		return err
	}
	if len(r.ChartRows) > 0 || r.ChartOther != nil || r.Query.View != "table" && r.Query.View != "matrix" {
		if err := p.groups(c, "chart_groups", r.Query.GroupBy, r.ChartRows, r.ChartOther, nil); err != nil {
			return err
		}
	}
	if len(r.Series) > 0 || len(r.OtherSeries) > 0 || len(r.TotalSeries) > 0 || r.Query.View != "table" {
		if err := p.points(c); err != nil {
			return err
		}
	}
	if len(r.MatrixRows) > 0 || len(r.MatrixColumns) > 0 || len(r.Matrix) > 0 || r.Query.View == "matrix" {
		if err := p.groups(c, "matrix_rows", r.Query.GroupBy, r.MatrixRows, nil, nil); err != nil {
			return err
		}
		if err := p.groups(c, "matrix_columns", r.Query.MatrixWith, r.MatrixColumns, nil, nil); err != nil {
			return err
		}
		if err := p.matrix(c); err != nil {
			return err
		}
	}
	return nil
}

func (p *reportFlowProjection) validate(c capturedReportFlow) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if c.TenantID != p.tenant || c.ID == "" || c.Name == "" || c.Period != "current" && c.Period != "previous" {
		return apierror.Forbidden("captured report source scope is unavailable")
	}
	for _, value := range []string{c.ID, c.Name, c.Version} {
		if !utf8.ValidString(value) {
			return apierror.Validation("report source identity is not complete UTF-8")
		}
	}
	if _, err := flow.QueryViewVersion(c.Version); err != nil {
		return apierror.Validation("report source requires its exact saved-query version")
	}
	r := c.Result
	if r.Query.From.IsZero() || !r.Query.To.After(r.Query.From) || r.Coverage == nil || !r.Coverage.CompleteInputs || r.Source != "raw" && r.Source != "rollup" {
		return apierror.Validation("report source requires complete scoped input coverage")
	}
	if len(r.Query.Metrics) == 0 || r.TotalGroups < 0 || r.Totals == nil {
		return apierror.Validation("report source metric schema is unavailable")
	}
	if int64(len(r.Query.GroupBy))+int64(len(r.Query.MatrixWith))+int64(len(r.Query.Metrics))+int64(len(r.TagIDs))+int64(len(r.Coverage.Fields)) > p.memory/256 {
		return reportProjectionLimit()
	}
	if r.TagRevision > 0 {
		if r.TagTenantID != p.tenant || c.TagAsOf.IsZero() {
			return apierror.Forbidden("report metadata capture scope is unavailable")
		}
	} else if r.TagTenantID != "" || len(r.TagIDs) > 0 || !c.TagAsOf.IsZero() {
		return apierror.Validation("report metadata clock is not bound to a captured revision")
	}
	fields := append(append(append([]string(nil), r.Query.GroupBy...), r.Query.MatrixWith...), flow.QueryFilterFields(r.Query.Filter)...)
	fields = append(fields, r.Coverage.Fields...)
	wanted := map[string]bool{}
	for _, field := range fields {
		if strings.HasPrefix(field, "tag.") {
			wanted[field] = true
			if r.TagRevision <= 0 || r.TagIDs[field] == "" {
				return apierror.Validation("report source lost an immutable tag field identity")
			}
		}
	}
	for name, id := range r.TagIDs {
		if !wanted[name] || id == "" {
			return apierror.Validation("report source field identity differs from its selected inputs")
		}
	}
	if err := p.charge(512 + int64(len(fields))*128); err != nil {
		return err
	}
	return nil
}

func reportFlowMetrics(plan flow.QueryPlan) []reporting.CSVColumn {
	columns := make([]reporting.CSVColumn, 0, len(plan.Metrics))
	for _, metric := range plan.Metrics {
		columns = append(columns, reporting.CSVColumn{Name: metric.Measure + ":" + metric.Calculation, Numeric: true})
	}
	return columns
}

func reportFlowFields(fields []string, prefix string) []reporting.CSVColumn {
	columns := make([]reporting.CSVColumn, 0, len(fields))
	for _, name := range fields {
		columns = append(columns, reporting.CSVColumn{Name: prefix + name})
	}
	return columns
}

func reportFlowFieldIDs(c capturedReportFlow, columns []reporting.CSVColumn) map[string]string {
	ids := map[string]string{}
	for _, column := range columns {
		name := column.Name
		name = strings.TrimPrefix(name, "row.")
		name = strings.TrimPrefix(name, "column.")
		if id := c.Result.TagIDs[name]; id != "" {
			ids[column.Name] = id
		}
	}
	return ids
}

func reportFlowValues(fields []string, group map[string]string, blank bool) ([]string, error) {
	row := make([]string, len(fields))
	if blank {
		return row, nil
	}
	for i, name := range fields {
		value, ok := group[name]
		if !ok {
			return nil, apierror.Validation("report source omitted a selected group field")
		}
		row[i] = value
	}
	return row, nil
}

func appendReportFlowMetrics(row []string, columns []reporting.CSVColumn, metrics map[string]string) ([]string, error) {
	for _, column := range columns {
		value, ok := metrics[column.Name]
		if !ok || len(value) > 256 || !flowCSVDecimal.MatchString(value) {
			return nil, apierror.Validation("report source omitted or changed an exact numeric metric")
		}
		row = append(row, value)
	}
	return row, nil
}

func (p *reportFlowProjection) groups(c capturedReportFlow, section string, fields []string, groups []flowstore.PlanRow, other *flowstore.PlanRow, totals map[string]string) error {
	metrics := reportFlowMetrics(c.Result.Query)
	columns := []reporting.CSVColumn{{Name: "record_type"}, {Name: "is_other"}}
	columns = append(columns, reportFlowFields(fields, "")...)
	columns = append(columns, metrics...)
	count := len(groups)
	if other != nil {
		count++
	}
	if totals != nil {
		count++
	}
	return p.table(c, section, columns, reportFlowFieldIDs(c, columns), count, func(i int) ([]string, error) {
		kind := "detail"
		var item flowstore.PlanRow
		switch {
		case i < len(groups):
			item = groups[i]
		case other != nil && i == len(groups):
			item = *other
			kind = "other"
		default:
			kind = "totals"
			item.Metrics = totals
		}
		if section == "detail" && (kind == "detail" && item.Other || kind == "other" && !item.Other) {
			return nil, apierror.Validation("report source group kind changed")
		}
		values, err := reportFlowValues(fields, item.Group, item.Other || kind == "totals")
		if err != nil {
			return nil, err
		}
		row := append([]string{kind, strconv.FormatBool(item.Other)}, values...)
		return appendReportFlowMetrics(row, metrics, item.Metrics)
	})
}

func (p *reportFlowProjection) points(c capturedReportFlow) error {
	r := c.Result
	metrics := reportFlowMetrics(r.Query)
	columns := []reporting.CSVColumn{{Name: "record_type"}, {Name: "is_other"}, {Name: "event_time"}, {Name: "duration_seconds", Numeric: true}}
	columns = append(columns, reportFlowFields(r.Query.GroupBy, "")...)
	columns = append(columns, metrics...)
	count := len(r.Series) + len(r.OtherSeries) + len(r.TotalSeries)
	return p.table(c, "points", columns, reportFlowFieldIDs(c, columns), count, func(i int) ([]string, error) {
		kind := "point"
		var item flowstore.PlanPoint
		switch {
		case i < len(r.Series):
			item = r.Series[i]
		case i < len(r.Series)+len(r.OtherSeries):
			item = r.OtherSeries[i-len(r.Series)]
			kind = "other_point"
		default:
			item = r.TotalSeries[i-len(r.Series)-len(r.OtherSeries)]
			kind = "total_point"
		}
		if item.TS.IsZero() || len(item.DurationSeconds) > 256 || !flowCSVDecimal.MatchString(item.DurationSeconds) || strings.Trim(item.DurationSeconds, "0.") == "" {
			return nil, apierror.Validation("report source point clock is unavailable")
		}
		if kind == "point" && item.Other || kind == "other_point" && !item.Other || kind == "total_point" && item.Other {
			return nil, apierror.Validation("report source point kind changed")
		}
		values, err := reportFlowValues(r.Query.GroupBy, item.Group, item.Other || kind == "total_point")
		if err != nil {
			return nil, err
		}
		row := append([]string{kind, strconv.FormatBool(item.Other), item.TS.UTC().Format(time.RFC3339Nano), item.DurationSeconds}, values...)
		return appendReportFlowMetrics(row, metrics, item.Metrics)
	})
}

func (p *reportFlowProjection) matrix(c capturedReportFlow) error {
	r := c.Result
	metrics := reportFlowMetrics(r.Query)
	columns := []reporting.CSVColumn{{Name: "row_is_other"}, {Name: "column_is_other"}}
	columns = append(columns, reportFlowFields(r.Query.GroupBy, "row.")...)
	columns = append(columns, reportFlowFields(r.Query.MatrixWith, "column.")...)
	columns = append(columns, metrics...)
	return p.table(c, "matrix_cells", columns, reportFlowFieldIDs(c, columns), len(r.Matrix), func(i int) ([]string, error) {
		cell := r.Matrix[i]
		row, err := reportFlowValues(r.Query.GroupBy, cell.Row, cell.RowOther)
		if err != nil {
			return nil, err
		}
		column, err := reportFlowValues(r.Query.MatrixWith, cell.Column, cell.ColumnOther)
		if err != nil {
			return nil, err
		}
		values := append([]string{strconv.FormatBool(cell.RowOther), strconv.FormatBool(cell.ColumnOther)}, row...)
		values = append(values, column...)
		return appendReportFlowMetrics(values, metrics, cell.Metrics)
	})
}

func (p *reportFlowProjection) table(c capturedReportFlow, section string, columns []reporting.CSVColumn, ids map[string]string, count int, row func(int) ([]string, error)) error {
	if int64(count) > p.rows {
		return reportProjectionLimit()
	}
	p.rows -= int64(count)
	if int64(count) > p.memory/64 || int64(len(columns)) > p.memory/128 {
		return reportProjectionLimit()
	}
	if err := p.charge(int64(count)*64 + int64(len(columns))*128 + 512); err != nil {
		return err
	}
	id := c.ID + "/" + c.Version + "/" + c.Period + "/" + section
	if p.identities[id] {
		return apierror.Validation("report source table identities are repeated")
	}
	p.identities[id] = true
	for _, column := range columns {
		if err := p.charge(int64(len(column.Name))*2 + 64); err != nil {
			return err
		}
	}
	values := make([][]string, 0, count)
	for i := 0; i < count; i++ {
		if err := p.ctx.Err(); err != nil {
			return err
		}
		if int64(len(columns)) > p.memory/32 {
			return reportProjectionLimit()
		}
		if err := p.charge(int64(len(columns)) * 32); err != nil {
			return err
		}
		cells, err := row(i)
		if err != nil {
			return err
		}
		if len(cells) != len(columns) {
			return apierror.Validation("report source record width changed")
		}
		for j, value := range cells {
			if !utf8.ValidString(value) {
				return apierror.Validation("report source record is not complete UTF-8")
			}
			if int64(len(value)) > p.memory/2 {
				return reportProjectionLimit()
			}
			if err := p.charge(int64(len(value)) * 2); err != nil {
				return err
			}
			cells[j] = strings.Clone(value)
		}
		values = append(values, cells)
	}
	fields := make(map[string]string, len(ids))
	for key, value := range ids {
		if err := p.charge(int64(len(key)+len(value))*2 + 128); err != nil {
			return err
		}
		fields[strings.Clone(key)] = strings.Clone(value)
	}
	for _, value := range []string{id, c.Name, c.TenantID, c.Result.Source} {
		if err := p.charge(int64(len(value))*2 + 64); err != nil {
			return err
		}
	}
	table := reporting.CSVTable{ID: id, Title: c.Name + " / " + section + "; source_groups=" + strconv.Itoa(c.Result.TotalGroups) + "; detail_limited=" + strconv.FormatBool(c.Result.DetailLimited), TenantID: c.TenantID, Source: "flow:" + c.Result.Source, AbsoluteFrom: c.Result.Query.From, AbsoluteTo: c.Result.Query.To, Columns: append([]reporting.CSVColumn(nil), columns...), FieldIDs: fields, ExpectedRows: int64(count)}
	if c.Result.TagRevision > 0 {
		table.TagRevision = strconv.FormatInt(c.Result.TagRevision, 10)
		table.TagAsOf = c.TagAsOf
	}
	table.WalkRows = func(ctx context.Context, yield func([]string) error) error {
		for _, value := range values {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := yield(append([]string(nil), value...)); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	p.tables = append(p.tables, table)
	return nil
}
