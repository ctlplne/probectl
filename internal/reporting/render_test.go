// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
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
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-1.4")) || !bytes.Contains(pdfBytes, []byte(`Tenant: Acme \(tenant-a\)`)) {
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
	text := string(pdf)
	if strings.Contains(text, "omitted") {
		t.Error("valid exact values were omitted")
	}
	for i := range 100 {
		if !strings.Contains(text, fmt.Sprintf("metric-%03d: value-%03d", i, i)) {
			t.Errorf("missing metric %d", i)
		}
	}
	// Each Courier glyph is 6 points at 10pt. 88 glyphs fit inside 40pt
	// margins on a 612pt page. Escapes are PDF syntax, not extra glyphs.
	linePattern := regexp.MustCompile(`(?m)^\((.*)\) Tj$`)
	for _, match := range linePattern.FindAllStringSubmatch(text, -1) {
		line := strings.NewReplacer(`\(`, "(", `\)`, ")", `\\`, `\`).Replace(match[1])
		if len(line) > 88 {
			t.Errorf("line exceeds printable width: %d glyphs", len(line))
		}
	}
	pages := strings.Count(text, "/Type /Page /Parent")
	if pages < 3 {
		t.Errorf("expected pagination, got %d pages", pages)
	}
	if strings.Count(text, `Tenant: Acme \(tenant-a\)`) != pages {
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
	if !bytes.Contains(pdf, []byte("opaque value: left  right")) {
		t.Fatal("PDF changed significant whitespace in an exact value")
	}
}
