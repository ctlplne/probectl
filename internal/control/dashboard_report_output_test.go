// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportConfiguredOutputRetainsRowsAboveFormerLimits(t *testing.T) {
	for _, tc := range []struct {
		format string
		rows   int64
	}{{"csv", 1000001}, {"pdf", 8001}} {
		t.Run(tc.format, func(t *testing.T) {
			const tenant = "6e050eab-62bf-4bc7-901d-ab2f1d216813"
			ctx := tenancy.WithTenant(t.Context(), tenant)
			server := &Server{cfg: &config.Config{ReportCSVRows: 1000001, ReportPDFRows: 8001, ReportMaxBytes: 512 << 20}}
			budget := flowstore.DefaultExplorerBudget()
			budget.MemoryBytes = 1 << 30
			at := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
			doc := reporting.Document{Title: "Configured capacity", Preset: "operator", TenantName: "Owned capacity", TenantScope: tenant,
				AbsoluteFrom: at.Add(-time.Hour), AbsoluteTo: at, GeneratedAt: at, GeneratedBy: "operator",
				Provenance: []string{"generated complete-row component"}, RedactionState: "none", CoverageLimitations: []string{"renderer component, not real sender proof"}}
			doc.Tables = []reporting.CSVTable{{ID: "capacity", Title: "Capacity rows", TenantID: tenant, Source: "flow",
				AbsoluteFrom: doc.AbsoluteFrom, AbsoluteTo: doc.AbsoluteTo, Columns: []reporting.CSVColumn{{Name: "capacity_row"}}, ExpectedRows: tc.rows,
				WalkRows: func(ctx context.Context, yield func([]string) error) error {
					for i := int64(0); i < tc.rows; i++ {
						if err := ctx.Err(); err != nil {
							return err
						}
						if err := yield([]string{fmt.Sprintf("row-%07d", i)}); err != nil {
							return err
						}
					}
					return nil
				}}}
			stage, _, err := stageSourceDashboardReport(ctx, tc.format, doc, budget, server.reportOutputPolicy())
			if err != nil {
				t.Fatal("configured complete output above former row/body admission refused", err)
			}
			defer func() { _ = stage.Close() }()
			reader, err := stage.Open(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reader.Close() }()
			if tc.format == "csv" {
				assertConfiguredCSVRows(t, reader, tc.rows)
			} else {
				assertConfiguredPDFRows(t, reader, tc.rows)
			}
		})
	}
}

func assertConfiguredCSVRows(t *testing.T, body io.Reader, expected int64) {
	t.Helper()
	reader := csv.NewReader(body)
	reader.FieldsPerRecord = -1
	var count int64
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(record) == 1 && strings.HasPrefix(record[0], "row-") {
			if record[0] != fmt.Sprintf("row-%07d", count) {
				t.Fatal("configured CSV row missing, duplicated or out of order", count, record)
			}
			count++
		}
	}
	if count != expected {
		t.Fatal("configured CSV output incomplete", count, expected)
	}
}

func assertConfiguredPDFRows(t *testing.T, body io.Reader, expected int64) {
	t.Helper()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var text strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		const prefix = "/Span << /ActualText <"
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		encoded, _, ok := strings.Cut(strings.TrimPrefix(line, prefix), ">")
		raw, err := hex.DecodeString(encoded)
		if !ok || err != nil || len(raw) < 2 || len(raw)%2 != 0 || raw[0] != 0xfe || raw[1] != 0xff {
			t.Fatal("invalid PDF semantic text")
		}
		units := make([]uint16, (len(raw)-2)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(raw[2+i*2:])
		}
		text.WriteString(string(utf16.Decode(units)))
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile("row-([0-9]{7})").FindAllStringSubmatch(text.String(), -1)
	if int64(len(rows)) != expected {
		t.Fatal("configured PDF output incomplete", len(rows), expected)
	}
	for i, row := range rows {
		index, err := strconv.Atoi(row[1])
		if err != nil || index != i {
			t.Fatal("configured PDF row missing, duplicated or out of order", i, row)
		}
	}
}
