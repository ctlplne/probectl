// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func testDocument() Document {
	return Document{
		Title: "Network posture", Preset: "operator", TenantName: "Acme",
		TenantScope: "tenant-a", AbsoluteFrom: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
		AbsoluteTo:  time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		GeneratedAt: time.Date(2026, 7, 14, 12, 1, 0, 0, time.UTC), GeneratedBy: "operator@acme.test",
		Provenance: []string{"tenant-scoped control-plane APIs"}, RedactionState: "secrets removed",
		CoverageLimitations: []string{"devices without collectors are not observed"},
		Metrics:             map[string]string{"Active tests": "12", "Success rate": "99.5%"},
	}
}

func TestDashboardReportCarriesMandatoryScope(t *testing.T) {
	doc := testDocument()
	csvBytes, err := RenderCSV(doc)
	if err != nil {
		t.Fatalf("RenderCSV: %v", err)
	}
	rows, err := csv.NewReader(bytes.NewReader(csvBytes)).ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}
	joined := strings.Join(flattenRows(rows), "\n")
	for _, want := range []string{
		Banner, "tenant_name\nAcme", "tenant_scope\ntenant-a",
		"absolute_from\n2026-07-13T12:00:00Z", "generated_at\n2026-07-14T12:01:00Z",
		"provenance\ntenant-scoped control-plane APIs", "redaction_state\nsecrets removed",
		"coverage_limitations\ndevices without collectors are not observed", "Active tests\n12",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("CSV missing %q:\n%s", want, joined)
		}
	}

	pdfBytes, err := RenderPDF(doc)
	if err != nil {
		t.Fatalf("RenderPDF: %v", err)
	}
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-1.4")) || !strings.Contains(pdfSemanticText(t, pdfBytes), "Tenant: Acme (tenant-a)") {
		t.Fatalf("PDF does not carry a valid header and tenant scope: %q", pdfBytes[:min(len(pdfBytes), 120)])
	}
}

func TestDashboardReportRejectsMissingHonestyMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Document)
	}{
		{"time", func(d *Document) { d.AbsoluteTo = d.AbsoluteFrom }},
		{"provenance", func(d *Document) { d.Provenance = nil }},
		{"redaction", func(d *Document) { d.RedactionState = "" }},
		{"coverage", func(d *Document) { d.CoverageLimitations = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := testDocument()
			tc.mutate(&doc)
			if _, err := RenderCSV(doc); err == nil {
				t.Fatal("RenderCSV accepted an incomplete report")
			}
		})
	}
}

func flattenRows(rows [][]string) []string {
	var out []string
	for _, row := range rows {
		out = append(out, row...)
	}
	return out
}

func TestPDFWrapsDisclosuresAndPreservesAllMetrics(t *testing.T) {
	doc := testDocument()
	doc.Provenance = []string{strings.Repeat("tenant-scoped source ", 30)}
	doc.CoverageLimitations = []string{strings.Repeat("X", 240)}
	doc.Metrics = make(map[string]string)
	for i := range 100 {
		doc.Metrics[fmt.Sprintf("metric-%03d", i)] = fmt.Sprintf("value-%03d", i)
	}
	pdf, err := RenderPDF(doc)
	if err != nil {
		t.Fatal(err)
	}
	text := pdfSemanticText(t, pdf)
	if strings.Contains(text, "omitted") {
		t.Error("valid exact values were omitted")
	}
	for i := range 100 {
		if !strings.Contains(text, fmt.Sprintf("metric-%03d: value-%03d", i, i)) {
			t.Errorf("missing metric %d", i)
		}
	}
	// Check every positioned glyph, independently of the wrapping code.
	positions := regexp.MustCompile(`1 0 0 1 ([0-9.]+) ([0-9.]+) Tm`).FindAllStringSubmatch(string(pdf), -1)
	if len(positions) == 0 {
		t.Fatal("PDF contains no positioned glyphs")
	}
	for _, position := range positions {
		x, _ := strconv.ParseFloat(position[1], 64)
		y, _ := strconv.ParseFloat(position[2], 64)
		if x < 43.99 || x > 568.01 || y < 30 || y > 750 {
			t.Fatalf("positioned glyph escaped page margins: %v", position)
		}
	}

	pages := strings.Count(string(pdf), "/Type /Page /Parent")
	if pages < 2 {
		t.Errorf("expected pagination, got %d pages", pages)
	}
	if strings.Count(text, "Tenant: Acme (tenant-a)") != pages {
		t.Error("tenant scope must repeat on every page")
	}
	if strings.Count(text, "Absolute time:") != pages {
		t.Error("absolute interval must repeat on every page")
	}
	if strings.Contains(text, "probectl ?") {
		t.Error("built-in banner uses an unrenderable separator")
	}
}

func TestPDFRejectsHeaderThatCannotFitOnAPage(t *testing.T) {
	doc := testDocument()
	doc.TenantName = strings.Repeat("tenant", 1000)
	if _, err := RenderPDF(doc); err == nil {
		t.Fatal("oversized header must fail explicitly")
	}
}

func TestPDFPreservesWhitespaceInsideExactValues(t *testing.T) {
	doc := testDocument()
	doc.Metrics = map[string]string{"opaque value": "left  right"}
	pdf, err := RenderPDF(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pdfSemanticText(t, pdf), "opaque value: left  right") {
		t.Fatal("PDF changed significant whitespace in an exact value")
	}
}

func TestReportCSVPreservesCompleteLiteralTextAcrossEveryUntrustedField(t *testing.T) {
	for _, value := range []string{"=1+1", "+1", "-1", "@SUM(1)", "＝1+1", "＋1", "－1", "＠SUM(1)", " \ufeff＝1+1", "\tlabel", "\rlabel", "\nlabel", " =1,\"quoted\"\n" + strings.Repeat("🌐", 24000)} {
		t.Run(value[:min(len(value), 12)], func(t *testing.T) {
			doc := testDocument()
			doc.Title = value
			doc.TenantName = value
			doc.GeneratedBy = value
			doc.Provenance = []string{value}
			doc.RedactionState = value
			doc.CoverageLimitations = []string{value}
			doc.Metrics = map[string]string{value: value}
			encoded, err := RenderCSV(doc)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := csv.NewReader(bytes.NewReader(encoded)).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			fields := map[string]string{}
			for _, row := range rows {
				if len(row) != 2 {
					t.Fatal("CSV cell split changed report structure")
				}
				fields[row[0]] = row[1]
			}
			for _, name := range []string{"title", "tenant_name", "generated_by", "provenance", "redaction_state", "coverage_limitations"} {
				if fields[name] != "\t"+value {
					t.Fatalf("%s lost complete literal text", name)
				}
			}
			last := rows[len(rows)-1]
			if last[0] != "\t"+value || last[1] != "\t"+value {
				t.Fatal("metric name/value bypassed text encoding")
			}
			// The representation is explicitly quoted; the control prefix must not
			// escape CSV structure or mutate the original Document's stored values.
			if !bytes.Contains(encoded, []byte("\"\t")) || doc.Title != value || doc.Metrics[value] != value {
				t.Fatal("text encoding mutated source or left an unquoted prefix")
			}
		})
	}
	for _, value := range []string{"", "ordinary", "🌐 Unicode", "already 'quoted'", "18446744073709551616001", "line,\"quote\"\ncontinued"} {
		if CSVText(value) != value {
			t.Fatal("ordinary text changed")
		}
	}
}

// Decode PDF semantic text independently of the renderer's UTF-16 encoder.
// Poppler separately checks extraction and ink bounds in the CI PDF proof.
func pdfSemanticText(t *testing.T, body []byte) string {
	t.Helper()
	var out strings.Builder
	for _, match := range regexp.MustCompile(`/ActualText <([0-9A-F]+)>`).FindAllSubmatch(body, -1) {
		raw, err := hex.DecodeString(string(match[1]))
		if err != nil || len(raw) < 2 || len(raw)%2 != 0 || raw[0] != 0xfe || raw[1] != 0xff {
			t.Fatal("invalid PDF ActualText encoding")
		}
		units := make([]uint16, (len(raw)-2)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(raw[2+i*2 : 4+i*2])
		}
		out.WriteString(string(utf16.Decode(units)))
	}
	return out.String()
}
