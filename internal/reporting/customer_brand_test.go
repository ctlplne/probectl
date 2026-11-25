// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestCustomerReportIncludesAttributionAndLinkOnEveryPDFPage(t *testing.T) {
	doc := testDocument()
	doc.BrandName = "Northstar"
	rows := make([][]string, 90)
	for i := range rows {
		rows[i] = []string{fmt.Sprintf("record-%d", i)}
	}
	doc.Tables = []CSVTable{reportTable(doc, []CSVColumn{{Name: "identity"}}, rows)}
	csv, err := RenderCSV(doc)
	if err != nil || !bytes.Contains(csv, []byte("brand,Northstar")) ||
		!bytes.Contains(csv, []byte("powered_by,Powered by probectl")) ||
		!bytes.Contains(csv, []byte("powered_by_url,https://probectl.com")) {
		t.Fatal("CSV is missing its brand or attribution", err)
	}
	var pdf bytes.Buffer
	receipt, err := WritePDF(t.Context(), &pdf, doc, DefaultPDFLimits())
	if err != nil || receipt.Pages < 2 {
		t.Fatal("could not render the paginated branded report", err)
	}
	if links := bytes.Count(pdf.Bytes(), []byte("/URI (https://probectl.com)")); links != 2*receipt.Pages {
		t.Fatalf("expected one attribution link for each page header and footer, got %d links for %d pages", links, receipt.Pages)
	}
	if labels := bytes.Count(pdf.Bytes(), []byte("/Contents (Powered by probectl)")); labels != 2*receipt.Pages {
		t.Fatalf("expected readable names for both links on every page, got %d names for %d pages", labels, receipt.Pages)
	}
	pageLinks := regexp.MustCompile(`/Annots \[[0-9]+ 0 R [0-9]+ 0 R\]`)
	if linkedPages := len(pageLinks.FindAllIndex(pdf.Bytes(), -1)); linkedPages != receipt.Pages {
		t.Fatalf("expected both links to be attached to each page, got %d linked pages out of %d", linkedPages, receipt.Pages)
	}
	if footers := bytes.Count(pdf.Bytes(), []byte("/Rect [44 40 163 59]")); footers != receipt.Pages {
		t.Fatalf("expected a separate footer link on each page, got %d footers for %d pages", footers, receipt.Pages)
	}
	text := pdfSemanticText(t, pdf.Bytes())
	if !strings.Contains(text, "Northstar") || strings.Count(text, "Powered by probectl") < receipt.Pages+1 {
		t.Fatal("PDF omitted visible customer identity or a repeating attribution footer")
	}

	t.Run("name outside the bundled fonts", func(t *testing.T) {
		doc := testDocument()
		doc.BrandName = "Northstar \U0010FFFD"
		pdf, err := RenderPDF(doc)
		if err != nil {
			t.Fatal("unsupported brand glyph prevented report delivery", err)
		}
		if text := pdfSemanticText(t, pdf); !strings.Contains(text, doc.BrandName) {
			t.Fatal("PDF text layer lost the original name")
		}
		if !bytes.Contains(pdf, []byte("/URI (https://probectl.com)")) {
			t.Fatal("PDF lost the fixed attribution link")
		}
	})
}
