// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const reportRecordTenant = "00000000-0000-0000-0000-000000000001"
const reportRecordFieldID = "00000000-0000-0000-0000-000000000010"
const reportRecordLiteral = "＝SUM(1,2) 東京/العربية/🚀"

func reportRecordFixture() capturedReportFlow {
	at := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	rowFields := []string{"tag.customer", "protocol", "src_addr", "dst_addr", "src_port", "dst_port", "in_if", "exporter"}
	colFields := []string{"tag.customer", "transport", "src_addr", "dst_addr", "src_port", "dst_port", "out_if", "exporter"}
	group := func(fields []string, label string) map[string]string {
		out := map[string]string{}
		for _, field := range fields {
			out[field] = field + "=" + label
		}
		out["tag.customer"] = label
		return out
	}
	metrics := func(value string) map[string]string {
		return map[string]string{"bytes:total": value, "bytes:p95": value, "bytes:p99": value}
	}
	row, col := group(rowFields, reportRecordLiteral), group(colFields, "independent-column 東京")
	result := flowstore.PlanResult{Query: flow.QueryPlan{From: at, To: at.Add(time.Hour), View: "matrix", GroupBy: rowFields, MatrixWith: colFields, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "bytes", Calculation: "p95", Role: "secondary"}, {Measure: "bytes", Calculation: "p99", Role: "additional"}}}, Source: "raw", Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: true}, TagRevision: 9223372036854775806, TagTenantID: reportRecordTenant, TagIDs: map[string]string{"tag.customer": reportRecordFieldID}, TotalGroups: 2, DetailLimited: true}
	result.Rows = []flowstore.PlanRow{{Group: row, Metrics: metrics("9007199254740993")}}
	result.Other = &flowstore.PlanRow{Other: true, Metrics: metrics("1")}
	result.Totals = metrics("9007199254740994")
	result.ChartRows = []flowstore.PlanRow{{Group: row, Metrics: metrics("9007199254740993")}}
	result.ChartOther = &flowstore.PlanRow{Other: true, Metrics: metrics("1")}
	result.Series = []flowstore.PlanPoint{{Group: row, TS: at, DurationSeconds: "60", Metrics: metrics("9007199254740993")}}
	result.OtherSeries = []flowstore.PlanPoint{{Other: true, TS: at, DurationSeconds: "60", Metrics: metrics("1")}}
	result.TotalSeries = []flowstore.PlanPoint{{TS: at, DurationSeconds: "60", Metrics: metrics("9007199254740994")}}
	result.MatrixRows = []flowstore.PlanRow{{Group: row, Metrics: metrics("9007199254740993")}}
	result.MatrixColumns = []flowstore.PlanRow{{Group: col, Metrics: metrics("9007199254740993")}}
	result.Matrix = []flowstore.PlanMatrixCell{{Row: row, Column: col, Metrics: metrics("9007199254740993")}}
	return capturedReportFlow{TenantID: reportRecordTenant, ID: "saved-view", Version: "9007199254740993", Name: "Whole source", Period: "current", TagAsOf: at.Add(time.Hour), Result: result}
}

func TestReportFlowProjectionPreservesCompleteSections(t *testing.T) {
	t.Run("success", reportFlowCompleteSections)
}

func reportFlowCompleteSections(t *testing.T) {
	c := reportRecordFixture()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(c.TenantID))
	tables, err := projectReportFlowRecords(ctx, []capturedReportFlow{c}, 4<<20, 500000)
	if err != nil {
		t.Fatal(err)
	}
	sections := map[string]reporting.CSVTable{}
	for _, table := range tables {
		parts := strings.Split(table.ID, "/")
		sections[parts[len(parts)-1]] = table
	}
	if _, ok := sections["matrix_cells"]; !ok {
		t.Fatal("complete report matrix cells are missing")
	}
	wantCounts := map[string]int64{"field_identities": 1, "detail": 3, "chart_groups": 2, "points": 3, "matrix_rows": 1, "matrix_columns": 1, "matrix_cells": 1}
	if len(sections) != len(wantCounts) {
		t.Fatal("complete report source sections changed")
	}
	for name, want := range wantCounts {
		table, ok := sections[name]
		if !ok || table.ExpectedRows != want || table.TenantID != c.TenantID || table.TagRevision != "9223372036854775806" || !table.TagAsOf.Equal(c.TagAsOf) || !table.AbsoluteFrom.Equal(c.Result.Query.From) || !table.AbsoluteTo.Equal(c.Result.Query.To) {
			t.Fatalf("section %s lost complete rows or exact capture metadata: %+v", name, table)
		}
		rows := readReportRecordRows(t, table)
		if int64(len(rows)) != want {
			t.Fatalf("section %s omitted records", name)
		}
	}
	matrix := sections["matrix_cells"]
	cells := readReportRecordRows(t, matrix)[0]
	if len(cells) != 21 {
		t.Fatal("full eight-by-eight axis fields or all metrics were shortened")
	}
	for i, name := range c.Result.Query.GroupBy {
		if matrix.Columns[2+i].Name != "row."+name || cells[2+i] != c.Result.Matrix[0].Row[name] {
			t.Fatal("row axis key or complete literal value changed")
		}
	}
	for i, name := range c.Result.Query.MatrixWith {
		if matrix.Columns[10+i].Name != "column."+name || cells[10+i] != c.Result.Matrix[0].Column[name] {
			t.Fatal("independent column axis changed")
		}
	}
	for _, value := range cells[18:] {
		if value != "9007199254740993" {
			t.Fatal("exact matrix numeric string changed")
		}
	}
	if matrix.FieldIDs["row.tag.customer"] != reportRecordFieldID || matrix.FieldIDs["column.tag.customer"] != reportRecordFieldID {
		t.Fatal("axis-qualified immutable field identity changed")
	}
	// Captured records and IDs cannot be changed by a later query/rule mutation,
	// nor by a renderer that modifies the temporary yielded slice.
	c.Result.Matrix[0].Row["tag.customer"] = "later rule"
	c.Result.Matrix[0].Metrics["bytes:total"] = "0"
	c.Result.TagIDs["tag.customer"] = "replacement"
	if err := matrix.WalkRows(ctx, func(row []string) error { row[2] = "renderer mutation"; return nil }); err != nil {
		t.Fatal(err)
	}
	if got := readReportRecordRows(t, matrix)[0]; got[2] != reportRecordLiteral || got[18] != "9007199254740993" || matrix.FieldIDs["row.tag.customer"] != reportRecordFieldID {
		t.Fatal("frozen report records changed after capture")
	}
	doc := reportProjectionDocument(c.TenantID, tables)
	body, err := reporting.RenderCSV(doc)
	if err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var identity, cell bool
	for _, record := range records {
		if reflect.DeepEqual(record, []string{"table_field_id:column.tag.customer", reportRecordFieldID}) {
			identity = true
		}
		if len(record) == 21 && record[2] == "\t"+reportRecordLiteral && record[18] == "9007199254740993" {
			cell = true
		}
	}
	if !identity || !cell {
		t.Fatal("report CSV lost full field identity, one literal prefix or exact cell")
	}
	filter := reportRecordFixture()
	filter.Result.Query.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.site", Op: flow.QueryEqual, Values: []string{"AMS"}}}}
	filter.Result.TagIDs["tag.site"] = "00000000-0000-0000-0000-000000000011"
	projected, err := projectReportFlowRecords(ctx, []capturedReportFlow{filter}, 4<<20, 500000)
	if err != nil {
		t.Fatal(err)
	}
	if projected[0].ExpectedRows != 2 {
		t.Fatal("filter-only immutable field identity was omitted")
	}
}

func readReportRecordRows(t *testing.T, table reporting.CSVTable) [][]string {
	t.Helper()
	var rows [][]string
	if err := table.WalkRows(t.Context(), func(row []string) error { rows = append(rows, append([]string(nil), row...)); return nil }); err != nil {
		t.Fatal(err)
	}
	return rows
}

func reportProjectionDocument(tenant string, tables []reporting.CSVTable) reporting.Document {
	at := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	return reporting.Document{Title: "Captured source", Preset: "operator", TenantName: "Fixture", TenantScope: tenant, AbsoluteFrom: at, AbsoluteTo: at.Add(time.Hour), GeneratedAt: at.Add(time.Hour), GeneratedBy: "fixture", Provenance: []string{"synthetic source-projection component proof"}, RedactionState: "no secrets", CoverageLimitations: []string{"not a live report-source or sender proof"}, Tables: tables}
}

func TestReportFlowProjectionScopesSourcesAndWholeBatchRefusal(t *testing.T) {
	const blue = "00000000-0000-0000-0000-000000000002"
	at := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	store := flowstore.NewMemory()
	if err := store.Insert(t.Context(), []flowstore.Row{{TenantID: reportRecordTenant, TS: at, Exporter: "192.0.2.1", Protocol: "RED_ONLY", BytesScaled: 9007199254740993}, {TenantID: blue, TS: at, Exporter: "192.0.2.1", Protocol: "BLUE_ONLY", BytesScaled: 9007199254740994}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ tenant, want, foreign, exact string }{{reportRecordTenant, "RED_ONLY", "BLUE_ONLY", "9007199254740993"}, {blue, "BLUE_ONLY", "RED_ONLY", "9007199254740994"}} {
		result, err := store.ExplorePlan(t.Context(), flowstore.PlanQuery{TenantID: tc.tenant, Plan: flow.QueryPlan{From: at, To: at.Add(time.Hour), View: "table", GroupBy: []string{"protocol"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}})
		if err != nil {
			t.Fatal(err)
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tc.tenant))
		capture := capturedReportFlow{TenantID: tc.tenant, ID: "same-view", Version: "1", Name: "Same private exporter", Period: "current", Result: result}
		tables, err := projectReportFlowRecords(ctx, []capturedReportFlow{capture}, 1<<20, 500000)
		if err != nil {
			t.Fatal(err)
		}
		body, err := reporting.RenderCSV(reportProjectionDocument(tc.tenant, tables))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte(tc.want)) || !bytes.Contains(body, []byte(tc.exact)) || bytes.Contains(body, []byte(tc.foreign)) {
			t.Fatal("report projection mixed same-address tenant values or precision")
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*capturedReportFlow)
	}{
		{"foreign", func(c *capturedReportFlow) { c.TenantID = blue }},
		{"foreign_tag_receipt", func(c *capturedReportFlow) { c.Result.TagTenantID = blue }},
		{"missing_clock", func(c *capturedReportFlow) { c.TagAsOf = time.Time{} }},
		{"missing_id", func(c *capturedReportFlow) { delete(c.Result.TagIDs, "tag.customer") }},
		{"fake_legacy_clock", func(c *capturedReportFlow) {
			c.Result.TagRevision = 0
			c.Result.TagTenantID = ""
			c.Result.TagIDs = nil
		}},
		{"missing_metric", func(c *capturedReportFlow) { delete(c.Result.Matrix[0].Metrics, "bytes:p99") }},
		{"missing_group", func(c *capturedReportFlow) { delete(c.Result.Matrix[0].Column, "out_if") }},
		{"missing_totals", func(c *capturedReportFlow) { c.Result.Totals = nil }},
		{"incomplete_source", func(c *capturedReportFlow) { c.Result.Coverage.CompleteInputs = false }},
		{"bad_version", func(c *capturedReportFlow) { c.Version = "1e4" }},
		{"bad_point", func(c *capturedReportFlow) { c.Result.TotalSeries[0].DurationSeconds = "0.0" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := reportRecordFixture()
			tc.change(&c)
			if tables, err := projectReportFlowRecords(tenancy.WithTenant(t.Context(), tenancy.ID(reportRecordTenant)), []capturedReportFlow{c}, 4<<20, 500000); err == nil || tables != nil {
				t.Fatal("incomplete or foreign capture produced report tables")
			}
		})
	}
	c := reportRecordFixture()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(c.TenantID))
	for _, limits := range [][2]int64{{64, 500000}, {4 << 20, 11}} {
		if tables, err := projectReportFlowRecords(ctx, []capturedReportFlow{c}, limits[0], limits[1]); err == nil || tables != nil {
			t.Fatal("complete projection budget was not enforced")
		}
	}
	second := reportRecordFixture()
	second.ID = "second-source"
	if tables, err := projectReportFlowRecords(ctx, []capturedReportFlow{c, second}, 4<<20, 23); err == nil || tables != nil {
		t.Fatal("projection reset its row budget per source")
	}
	if tables, err := projectReportFlowRecords(ctx, []capturedReportFlow{c, c}, 4<<20, 500000); err == nil || tables != nil {
		t.Fatal("repeated source table identity was accepted")
	}
	if tables, err := projectReportFlowRecords(t.Context(), []capturedReportFlow{c}, 4<<20, 500000); err == nil || tables != nil {
		t.Fatal("tenantless projection was accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if tables, err := projectReportFlowRecords(canceled, []capturedReportFlow{c}, 4<<20, 500000); !errors.Is(err, context.Canceled) || tables != nil {
		t.Fatal("canceled projection returned partial tables")
	}
	tables, err := projectReportFlowRecords(ctx, []capturedReportFlow{c}, 4<<20, 500000)
	if err != nil {
		t.Fatal(err)
	}
	if err := tables[0].WalkRows(ctx, func([]string) error { return io.ErrClosedPipe }); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("projection ignored a consumer failure")
	}
}
