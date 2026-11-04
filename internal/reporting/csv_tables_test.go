// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func reportTable(d Document, columns []CSVColumn, rows [][]string) CSVTable {
	return CSVTable{
		ID: "query-1", Title: "Current metadata over retained traffic", TenantID: d.TenantScope,
		Source: "flow", AbsoluteFrom: d.AbsoluteFrom, AbsoluteTo: d.AbsoluteTo,
		TagRevision: "9223372036854775806", TagAsOf: d.GeneratedAt,
		Columns: columns, ExpectedRows: int64(len(rows)),
		WalkRows: func(ctx context.Context, yield func([]string) error) error {
			for _, row := range rows {
				if err := yield(row); err != nil {
					return err
				}
			}
			return ctx.Err()
		},
	}
}

func TestReportCSVStreamsCompleteLineItemReachAndExactCells(t *testing.T) {
	t.Run("success", reportCSVCompleteLineItems)
}

func reportCSVCompleteLineItems(t *testing.T) {
	d := testDocument()
	columns := []CSVColumn{{Name: "sequence", Numeric: true}, {Name: "tag:customer"}, {Name: "bytes", Numeric: true}, {Name: "delta", Numeric: true}}
	table := reportTable(d, columns, nil)
	table.ExpectedRows = 500_000
	table.WalkRows = func(ctx context.Context, yield func([]string) error) error {
		for i := int64(0); i < 500_000; i++ {
			if err := yield([]string{strconv.FormatInt(i, 10), "東京/موقع/🚀", strconv.FormatInt(9_007_199_254_740_993+i, 10), "-1.125"}); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	d.Tables = []CSVTable{table}
	file, err := os.Create(filepath.Join(t.TempDir(), "complete.csv"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	receipt, err := WriteCSV(context.Background(), file, d, DefaultCSVLimits())
	if err != nil {
		t.Fatalf("complete line-item source was refused: %v", err)
	}
	info, err := file.Stat()
	if err != nil || receipt.Bytes != info.Size() || receipt.TableRows != 500_000 {
		t.Fatalf("incomplete CSV receipt: %+v stat=%v error=%v", receipt, info, err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	found, revision, declared := false, false, false
	for !found {
		row, err := reader.Read()
		if err != nil {
			t.Fatalf("complete table header is missing: %v", err)
		}
		found = reflect.DeepEqual(row, []string{"sequence", "tag:customer", "bytes", "delta"})
		revision = revision || reflect.DeepEqual(row, []string{"table_tag_revision", "9223372036854775806"})
		declared = declared || reflect.DeepEqual(row, []string{"table_rows", "500000"})
	}
	if !revision || !declared {
		t.Fatal("complete table source clock or row count is missing")
	}
	for i := int64(0); i < 500_000; i++ {
		row, err := reader.Read()
		if err != nil || len(row) != 4 {
			t.Fatalf("logical table record %d is missing or malformed: %v %v", i, row, err)
		}
		sequence, seqErr := strconv.ParseInt(row[0], 10, 64)
		counter, counterErr := strconv.ParseInt(row[2], 10, 64)
		if seqErr != nil || counterErr != nil || sequence != i || counter-i != 9_007_199_254_740_993 || row[1] != "東京/موقع/🚀" || row[3] != "-1.125" {
			t.Fatalf("logical record %d lost identity, text or exact decimals: %q", i, row)
		}
		if i == 499_999 && row[2] != "9007199255240992" {
			t.Fatalf("last exact value changed: %q", row[2])
		}
	}
	if row, err := reader.Read(); err != io.EOF {
		t.Fatalf("unexpected records after complete table: %q %v", row, err)
	}
	t.Logf("CSV component: logical_rows=%d bytes=%d all_rows_independently_verified", receipt.TableRows, receipt.Bytes)
}

func TestReportCSVKeepsWholeUnicodeFormulaAndCRLFCells(t *testing.T) {
	d := testDocument()
	wide := "＝SUM(1,2) " + strings.Repeat("界🚀", 30_000) + "終\r\n末,\"quoted\""
	columns := []CSVColumn{{Name: "＝field"}, {Name: "tag:site"}, {Name: "bytes", Numeric: true}, {Name: "delta", Numeric: true}}
	d.Tables = []CSVTable{reportTable(d, columns, [][]string{{wide, "+SUM(1,2)", "9007199254740993", "-1"}})}
	body, err := RenderCSV(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("終\r\n末,")) {
		t.Fatal("CSV source bytes lost the embedded CRLF")
	}
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := []string{"\t＝field", "tag:site", "bytes", "delta"}
	// encoding/csv intentionally normalizes CRLF within quoted fields. Verify
	// raw preservation above, then its documented normalized parse separately.
	want := []string{"\t" + strings.ReplaceAll(wide, "\r\n", "\n"), "\t+SUM(1,2)", "9007199254740993", "-1"}
	if !reflect.DeepEqual(rows[len(rows)-2], wantHeader) || !reflect.DeepEqual(rows[len(rows)-1], want) {
		t.Fatal("complete field keys, wide literal cells or exact numeric cells changed")
	}
	if pdf, err := RenderPDF(d); err == nil || pdf != nil {
		t.Fatal("PDF silently accepted and omitted unsupported table records")
	}
}

func TestReportCSVRefusesIncompleteForeignOrMalformedSources(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CSVTable)
	}{
		{"foreign tenant", func(v *CSVTable) { v.TenantID = "tenant-b" }},
		{"missing source", func(v *CSVTable) { v.Source = "" }},
		{"bad interval", func(v *CSVTable) { v.AbsoluteTo = v.AbsoluteFrom }},
		{"replacement clock", func(v *CSVTable) { v.TagRevision = "01" }},
		{"missing clock", func(v *CSVTable) { v.TagRevision = "" }},
		{"duplicate fields", func(v *CSVTable) { v.Columns = append(v.Columns, v.Columns[0]) }},
		{"short source", func(v *CSVTable) { v.ExpectedRows = 2 }},
		{"extra source", func(v *CSVTable) { v.ExpectedRows = 0 }},
		{"wrong schema", func(v *CSVTable) { v.Columns = append(v.Columns, CSVColumn{Name: "missing"}) }},
		{"ignored callback failure", func(v *CSVTable) {
			v.WalkRows = func(_ context.Context, yield func([]string) error) error {
				_ = yield([]string{"1"})
				_ = yield([]string{"2"})
				return nil
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := testDocument()
			v := reportTable(d, []CSVColumn{{Name: "bytes", Numeric: true}}, [][]string{{"1"}})
			tc.mutate(&v)
			d.Tables = []CSVTable{v}
			if body, err := RenderCSV(d); err == nil || body != nil {
				t.Fatal("invalid source produced a publishable CSV")
			}
		})
	}
	for _, value := range []string{"", "+1", "01", "1e3", "1/2", "NaN", "1.", ".5", "=1", "1.2.3", "−1"} {
		t.Run("numeric "+value, func(t *testing.T) {
			d := testDocument()
			d.Tables = []CSVTable{reportTable(d, []CSVColumn{{Name: "bytes", Numeric: true}}, [][]string{{value}})}
			if body, err := RenderCSV(d); err == nil || body != nil {
				t.Fatal("invalid numeric cell produced a publishable CSV")
			}
		})
	}
}

func TestReportCSVWholeOperationBudgetsCancellationAndFailure(t *testing.T) {
	for _, kind := range []string{"bytes", "rows", "schema memory", "row memory", "legacy memory", "duplicate table", "canceled", "source", "sink", "short write"} {
		t.Run(kind, func(t *testing.T) {
			d := testDocument()
			v := reportTable(d, []CSVColumn{{Name: "tag:site"}}, [][]string{{strings.Repeat("界", 1024)}})
			d.Tables = []CSVTable{v}
			limits := DefaultCSVLimits()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			target := io.Discard
			var want error
			sentinel := errors.New("source or destination unavailable")
			switch kind {
			case "bytes":
				limits.Bytes, want = 1024, ErrCSVLimit
			case "rows":
				d.Tables[0].ExpectedRows, want = limits.TableRows+1, ErrCSVLimit
			case "schema memory":
				limits.MemoryBytes, want = 1, ErrCSVLimit
			case "row memory":
				limits.MemoryBytes, want = 8192, ErrCSVLimit
			case "legacy memory":
				d.Provenance = []string{strings.Repeat("界", 32_000)}
				limits.MemoryBytes, want = 8192, ErrCSVLimit
			case "duplicate table":
				d.Tables = append(d.Tables, v)
			case "canceled":
				d.Tables[0].WalkRows = func(_ context.Context, yield func([]string) error) error {
					cancel()
					_ = yield([]string{"owned"})
					return nil
				}
				want = context.Canceled
			case "source":
				d.Tables[0].WalkRows = func(context.Context, func([]string) error) error { return sentinel }
				want = sentinel
			case "sink":
				target, want = reportCSVFailWriter{sentinel}, sentinel
			case "short write":
				target, want = reportCSVFailWriter{}, io.ErrShortWrite
			}
			receipt, err := WriteCSV(ctx, target, d, limits)
			if err == nil || receipt != (CSVReceipt{}) || want != nil && !errors.Is(err, want) {
				t.Fatalf("failed output accepted or misclassified: receipt=%+v err=%v want=%v", receipt, err, want)
			}
		})
	}
	t.Run("context wrapper", func(t *testing.T) {
		type sourceContextKey struct{}
		ctx, cancel := context.WithCancel(context.WithValue(context.Background(), sourceContextKey{}, "actual operation"))
		defer cancel()
		d := testDocument()
		v := reportTable(d, []CSVColumn{{Name: "tag:site"}}, nil)
		v.ExpectedRows = 2
		v.WalkRows = func(sourceCtx context.Context, yield func([]string) error) error {
			if sourceCtx.Value(sourceContextKey{}) != "actual operation" {
				return errors.New("source lost the actual operation context")
			}
			if err := yield([]string{strings.Repeat("owned", 2048)}); err != nil {
				return err
			}
			cancel()
			return yield([]string{"second row"})
		}
		d.Tables = []CSVTable{v}
		body, err := RenderCSVContext(ctx, d)
		if !errors.Is(err, context.Canceled) || body != nil {
			t.Fatalf("canceled staged bytes became publishable or lost source context: bytes=%d err=%v", len(body), err)
		}
	})
}

type reportCSVFailWriter struct{ err error }

func (w reportCSVFailWriter) Write(body []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	return len(body) - 1, nil
}

func TestReportCSVLegacyBytesStayStable(t *testing.T) {
	want := "banner,probectl · tenant-scoped report\ntitle,Network posture\npreset,operator\n" +
		"tenant_name,Acme\ntenant_scope,tenant-a\nabsolute_from,2026-07-13T12:00:00Z\nabsolute_to,2026-07-14T12:00:00Z\n" +
		"generated_at,2026-07-14T12:01:00Z\ngenerated_by,operator@acme.test\nprovenance,tenant-scoped control-plane APIs\n" +
		"redaction_state,secrets removed\ncoverage_limitations,devices without collectors are not observed\n" +
		"metric,exact_value\nActive tests,12\nSuccess rate,99.5%\n"
	got, err := RenderCSV(testDocument())
	if err != nil || string(got) != want {
		t.Fatalf("legacy exact CSV changed: %v\n%s", err, got)
	}
}
