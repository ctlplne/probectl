// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func clientReportTableFixture(tenant string) (time.Time, time.Time, []clientReportAvailability, []clientReportSLO) {
	from := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	source := clientReportTestSelector{ContextID: "33333333-3333-4333-8333-333333333333", EntityID: "44444444-4444-4444-8444-444444444444", TestID: "55555555-5555-4555-8555-555555555555", AgentID: "month-agent", Name: "=SUM(1,2)\n東京", Type: "http", DefinitionDigest: strings.Repeat("a", 64), SourceGeneration: 1}
	counts := (clientReportOutcomeCounter{successful: 9007199254740993, failed: 7, unknown: 2, canceled: 1}).counts()
	availability := []clientReportAvailability{{TenantID: tenant, Source: source, From: from, To: to, Counts: counts, OriginalCount: "9007199254741002", OriginalsDigest: strings.Repeat("b", 64)}}
	meets := true
	objectives := []clientReportSLO{{TenantID: tenant, Name: "monthly-service", DisplayName: "Client service", DefinitionDigest: strings.Repeat("c", 64), ObjectiveRatio: "0.999", Basis: "current_definition_configured_window", From: to.Add(-45 * 24 * time.Hour), To: to, Counts: counts, Sources: []clientReportTestSelector{source}, OriginalCount: "9007199254741002", OriginalsDigest: strings.Repeat("d", 64), ObservedMeetsObjective: &meets},
		{TenantID: tenant, Name: "no-observations", DefinitionDigest: strings.Repeat("e", 64), ObjectiveRatio: "0.999", Basis: "current_definition_configured_window", From: from, To: to, Counts: (clientReportOutcomeCounter{}).counts(), Sources: []clientReportTestSelector{}, OriginalCount: "0", OriginalsDigest: strings.Repeat("f", 64)}}
	return from, to, availability, objectives
}

func TestClientReportTablesKeepExactCountsWindowsAndFrozenTenantSources(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		from, to, availability, objectives := clientReportTableFixture(tenant)
		tables, err := projectClientReportSLIs(ctx, tenant, from, to, availability, objectives, 1<<20)
		if err != nil || len(tables) != 2 || tables[0].ExpectedRows != 1 || tables[1].ExpectedRows != 2 || !tables[1].AbsoluteFrom.Equal(objectives[0].From) {
			t.Fatal("complete availability/SLO tables or configured windows were lost", err)
		}
		availability[0].Source.Name, availability[0].Counts.Successful = "mutated", "0"
		objectives[0].Sources[0].Name = "mutated"
		for index, table := range tables {
			rowIndex := 0
			err := table.WalkRows(ctx, func(row []string) error {
				values := map[string]string{}
				for column, cell := range row {
					values[table.Columns[column].Name] = cell
				}
				if values["tenant_id"] != tenant || (rowIndex == 0 && (values["successful"] != "9007199254740993" || values["original_count"] != "9007199254741002" || values["unknown"] != "2" || values["canceled"] != "1")) {
					t.Fatal("counts were rounded or borrowed from mutable/foreign inputs")
				}
				if index == 0 && values["test_name"] != "=SUM(1,2)\n東京" {
					t.Fatal("source identity/name changed during projection")
				}
				if index == 1 && rowIndex == 0 && (!strings.Contains(values["selected_sources"], "東京") || strings.Contains(values["selected_sources"], "mutated") || values["window_from"] != objectives[0].From.Format(time.RFC3339Nano)) {
					t.Fatal("complete selected sources or exact SLO interval was lost")
				}
				if index == 1 && rowIndex == 1 && (values["observed_meets_objective"] != "unknown" || values["coverage"] != "no_known_outcomes" || values["selected_sources"] != "[]") {
					t.Fatal("missing measurements became a healthy SLO")
				}
				row[0] = "renderer mutation"
				rowIndex++
				return nil
			})
			if err != nil || int64(rowIndex) != table.ExpectedRows {
				t.Fatal("complete table cursor failed", err)
			}
		}
		doc := reporting.Document{Title: "Monthly client report", TenantName: "Client", TenantScope: tenant, AbsoluteFrom: from, AbsoluteTo: to, GeneratedAt: to, Provenance: []string{"complete original-evidence query selection"}, RedactionState: "current source policy", CoverageLimitations: []string{"observed outcomes do not attest schedule completeness"}, Tables: tables}
		body, err := reporting.RenderCSVContext(ctx, doc)
		if err != nil {
			t.Fatal("shared CSV renderer refused complete monthly tables", err)
		}
		reader := csv.NewReader(strings.NewReader(string(body)))
		reader.FieldsPerRecord = -1
		records, err := reader.ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, record := range records {
			if len(record) == len(tables[0].Columns) && record[0] == tenant && record[3] == "55555555-5555-4555-8555-555555555555" {
				found = true
				if record[5] != "\t=SUM(1,2)\n東京" || record[9] != "9007199254740993" || record[16] != "9007199254741002" {
					t.Fatal("shared CSV renderer changed exact counts, frozen values or safe literal text")
				}
			}
		}
		if !found {
			t.Fatal("complete availability row disappeared from CSV output")
		}
		foreign := tenancy.WithTenant(t.Context(), tenancy.ID("foreign"))
		called := false
		if err := tables[0].WalkRows(foreign, func([]string) error { called = true; return nil }); !errors.Is(err, entity.ErrScopeMismatch) || called {
			t.Fatal("stored projection cursor disclosed another tenant's cells", err)
		}
	}
}

func TestClientReportTablesRefuseForeignPartialAndCanceledProjection(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	from, to, availability, objectives := clientReportTableFixture(tenant)
	objectives[1].TenantID = "foreign"
	if tables, err := projectClientReportSLIs(ctx, tenant, from, to, availability, objectives, 1<<20); !errors.Is(err, entity.ErrScopeMismatch) || tables != nil {
		t.Fatal("foreign late section returned an apparently usable table prefix", err)
	}
	objectives[1].TenantID = tenant
	if tables, err := projectClientReportSLIs(ctx, tenant, from, to, availability, objectives, 4096); err == nil || tables != nil {
		t.Fatal("complete table admission silently truncated rows")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if tables, err := projectClientReportSLIs(canceled, tenant, from, to, availability, objectives, 1<<20); !errors.Is(err, context.Canceled) || tables != nil {
		t.Fatal("canceled projection returned publishable tables", err)
	}
}
