// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

func TestReportPDFWholeUnicodeAndCompleteRows(t *testing.T) {
	d := testDocument()
	d.Metrics = map[string]string{"Unicode": "東京 العربية नमस्ते שָׁלוֹם ไทย e\u0301 🚀", "Literal": "＝SUM(1,2) \\ (quoted)  left  right"}
	rows := make([][]string, 4000)
	for i := range rows {
		rows[i] = []string{fmt.Sprintf("record-%04d", i), strconv.FormatInt(9_007_199_254_740_993+int64(i), 10)}
	}
	d.Tables = []CSVTable{reportTable(d, []CSVColumn{{Name: "identity"}, {Name: "exact_bytes", Numeric: true}}, rows)}
	var out bytes.Buffer
	receipt, err := WritePDF(context.Background(), &out, d, DefaultPDFLimits())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TableRows != 4000 || receipt.Bytes != int64(out.Len()) || receipt.Pages < 2 {
		t.Fatalf("incomplete PDF receipt: %+v", receipt)
	}
	semantic := pdfSemanticText(t, out.Bytes())
	for i := range rows {
		if strings.Count(semantic, rows[i][0]) != 1 || strings.Count(semantic, rows[i][1]) != 1 {
			t.Fatalf("PDF omitted or duplicated complete row %d", i)
		}
	}
	for _, word := range []string{"東京", "नमस्ते", "e\u0301", "🚀", "＝SUM(1,2)", "left  right"} {
		if !strings.Contains(semantic, word) {
			t.Fatalf("PDF lost Unicode or significant text: %q", word)
		}
	}
	t.Logf("PDF component: logical_rows=%d bytes=%d pages=%d all_rows_independently_verified", receipt.TableRows, receipt.Bytes, receipt.Pages)
}

func TestReportPDFRefusesIncompleteForeignAndUnrenderableSources(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Document)
	}{
		{"foreign", func(d *Document) { d.Tables[0].TenantID = "tenant-b" }},
		{"underflow", func(d *Document) { d.Tables[0].ExpectedRows = 2 }},
		{"overflow", func(d *Document) { d.Tables[0].ExpectedRows = 0 }},
		{"numeric", func(d *Document) { d.Tables[0].Columns[0].Numeric = true }},
		{"schema", func(d *Document) { d.Tables[0].Columns = append(d.Tables[0].Columns, CSVColumn{Name: "other"}) }},
		{"duplicate", func(d *Document) { d.Tables = append(d.Tables, d.Tables[0]) }},
		{"invalid_utf8", func(d *Document) { d.Title = string([]byte{0xff}) }},
		{"unsupported", func(d *Document) { d.Title = "missing \U0010ffff" }},
		{"nul", func(d *Document) { d.Title = "control\x00value" }},
		{"source_error", func(d *Document) {
			d.Tables[0].WalkRows = func(context.Context, func([]string) error) error { return io.ErrUnexpectedEOF }
		}},
		{"ignored_yield_error", func(d *Document) {
			d.Tables[0].WalkRows = func(_ context.Context, yield func([]string) error) error {
				_ = yield([]string{"one", "extra"})
				_ = yield([]string{"one"})
				return nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDocument()
			d.Tables = []CSVTable{reportTable(d, []CSVColumn{{Name: "value"}}, [][]string{{"literal"}})}
			tc.change(&d)
			body, err := RenderPDF(d)
			if err == nil || body != nil {
				t.Fatal("PDF published an incomplete, foreign or unrenderable source")
			}
		})
	}
	// A valid request after a missing-glyph failure cannot inherit its state.
	if _, err := RenderPDF(testDocument()); err != nil {
		t.Fatal(err)
	}
}

func TestReportPDFBudgetsCancellationWriterAndFontIntegrity(t *testing.T) {
	d := testDocument()
	d.Tables = []CSVTable{reportTable(d, []CSVColumn{{Name: "value"}}, [][]string{{"one"}, {"two"}})}
	for _, limits := range []PDFLimits{{Bytes: 64, TableRows: 4000, MemoryBytes: 128 << 20}, {Bytes: 256 << 20, TableRows: 1, MemoryBytes: 128 << 20}, {Bytes: 256 << 20, TableRows: 4000, MemoryBytes: 64}} {
		if _, err := WritePDF(context.Background(), io.Discard, d, limits); !errors.Is(err, ErrPDFLimit) {
			t.Fatalf("PDF budget was not enforced: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if body, err := RenderPDFContext(ctx, d); !errors.Is(err, context.Canceled) || body != nil {
		t.Fatal("cancelled PDF published output")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	d.Tables[0].WalkRows = func(_ context.Context, yield func([]string) error) error {
		cancel()
		_ = yield([]string{"one"})
		return nil
	}
	if body, err := RenderPDFContext(ctx, d); !errors.Is(err, context.Canceled) || body != nil {
		t.Fatal("source ignored cancellation and PDF published output")
	}
	if _, err := WritePDF(context.Background(), pdfShortWriter{}, testDocument(), DefaultPDFLimits()); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write was accepted: %v", err)
	}
	spec := pdfBundledFontSpecs[0]
	if _, err := parsePDFFonts(fstest.MapFS{spec.path: &fstest.MapFile{Data: []byte("corrupted")}}, []pdfFontSpec{spec}); err == nil {
		t.Fatal("corrupt bundled font passed provenance check")
	}
}

type pdfShortWriter struct{}

func (pdfShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

// CI invokes this root explicitly with an owned artifact directory. Normal
// unit runs still exercise the same specimen without requiring external tools.
func TestReportPDFIndependentSpecimen(t *testing.T) {
	d := testDocument()
	d.Title = "Unicode report proof"
	d.TenantName = "Acme 東京"
	d.Metrics = map[string]string{
		"latin":   "LATIN-BEGIN café naïve Straße e\u0301 LATIN-END",
		"arabic":  "ARABIC-BEGIN العربية موقع الشبكة ARABIC-END",
		"indic":   "INDIC-BEGIN नमस्ते दुनिया INDIC-END",
		"hebrew":  "HEBREW-BEGIN שָׁלוֹם HEBREW-END",
		"thai":    "THAI-BEGIN สวัสดี THAI-END",
		"cjk":     "CJK-BEGIN 東京 中文 CJK-END",
		"emoji":   "EMOJI-BEGIN 🚀 🌐 EMOJI-END",
		"literal": "LITERAL-BEGIN ＝SUM(1,2) (quoted) \\ left  right LITERAL-END",
		"wrapped": "WRAP-BEGIN " + strings.Repeat("complete-value ", 120) + "WRAP-END",
	}
	rows := make([][]string, 120)
	for i := range rows {
		rows[i] = []string{fmt.Sprintf("proof-row-%03d", i), strconv.FormatInt(9_007_199_254_740_993+int64(i), 10)}
	}
	d.Tables = []CSVTable{reportTable(d, []CSVColumn{{Name: "identity"}, {Name: "exact_bytes", Numeric: true}}, rows)}
	body, err := RenderPDF(d)
	if err != nil {
		t.Fatal(err)
	}
	semantic := pdfSemanticText(t, body)
	for _, row := range rows {
		if !strings.Contains(semantic, row[0]) || !strings.Contains(semantic, row[1]) {
			t.Fatal("independent PDF specimen omitted a captured row")
		}
	}
	if dir := os.Getenv("PROBECTL_PDF_PROOF_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "specimen.pdf"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
