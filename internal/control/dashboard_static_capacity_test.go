// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The corpus fits the existing public input contract. Unique supported glyphs
// exercise complete output capacity rather than repeated compressible filler.
func TestStaticReportKeepsCompleteValidatedMultilingualDocument(t *testing.T) {
	const tenant = "2a2534d2-823a-46eb-8530-bd2a68f2f822"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	at := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	next := rune(0x4e00)
	text := func(count int) string {
		value := make([]rune, count)
		for i := range value {
			value[i] = next
			next++
		}
		return string(value)
	}
	definition := dashboardDefinition{AbsoluteFrom: at.Add(-time.Hour), AbsoluteTo: at, RedactionState: "none", Metrics: map[string]string{}}
	for i := 0; i < 100; i++ {
		definition.Metrics[fmt.Sprintf("%02d", i)+text(26)] = text(80)
	}
	for range 20 {
		definition.Provenance = append(definition.Provenance, text(80))
		definition.CoverageLimitations = append(definition.CoverageLimitations, text(80))
	}
	input := dashboardCreateRequest{Name: "Complete static multilingual document", Preset: "operator", Definition: definition}
	validated, err := cleanDashboardCreate(input)
	if err != nil {
		t.Fatal("clean static capacity fixture rejected", err)
	}
	encoded, err := json.Marshal(validated)
	if err != nil || len(encoded) > maxDashboardManifestBytes {
		t.Fatal("clean static capacity fixture exceeds existing input envelope", len(encoded), err)
	}
	doc := reporting.Document{Title: validated.Name, Preset: validated.Preset, TenantName: "Owned static report", TenantScope: tenant, AbsoluteFrom: definition.AbsoluteFrom, AbsoluteTo: definition.AbsoluteTo, GeneratedAt: at, GeneratedBy: "operator", Provenance: definition.Provenance, RedactionState: definition.RedactionState, CoverageLimitations: definition.CoverageLimitations, Metrics: definition.Metrics}
	budget := flowstore.DefaultExplorerBudget()
	budget.MemoryBytes = 4 << 30
	policy := reporting.DefaultOutputPolicy()
	policy.Bytes = 64 << 20
	stage, _, err := stageSourceDashboardReport(ctx, "pdf", doc, budget, policy)
	if err != nil {
		t.Fatal("finite larger static reference profile refused validated document", err)
	}
	defer func() { _ = stage.Close() }()
	receipt, err := stage.Receipt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := stage.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := io.ReadAll(io.LimitReader(reader, policy.Bytes+1))
	closeErr := reader.Close()
	if err != nil || closeErr != nil || int64(len(reference)) != receipt.Bytes {
		t.Fatal("complete static reference read failed", err, closeErr)
	}
	t.Logf("unverified static reference: input_bytes=%d exact_metrics=%d provenance_entries=%d coverage_entries=%d reference_pdf_bytes=%d", len(encoded), len(doc.Metrics), len(doc.Provenance), len(doc.CoverageLimitations), receipt.Bytes)
	assertStaticDocumentSemanticText(t, reference, doc)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	actual, media, err := renderDashboardReport(ctx, "pdf", doc)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("static renderer refused complete validated document: complete_pdf_bytes=%d error=%v", receipt.Bytes, err)
	}
	if media != "application/pdf" {
		t.Fatal("static renderer changed media type")
	}
	assertStaticDocumentSemanticText(t, actual, doc)
	t.Logf("verified shipping static capacity: input_bytes=%d body_bytes=%d elapsed=%s heap_alloc_bytes=%d allocated_during_render=%d admission_bytes=%d; heap observations are not a peak or preallocation claim", len(encoded), len(actual), time.Since(started), after.HeapAlloc, after.TotalAlloc-before.TotalAlloc, int64(1)<<30)
}

// Decode standard UTF-16 ActualText spans independently of the renderer.
// Validate each page's furniture, then rejoin all body text in page order.
func staticDocumentSemanticText(body []byte, doc reporting.Document) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var pages []string
	var content strings.Builder
	inStream, semantic := false, false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "stream" {
			if inStream {
				return "", fmt.Errorf("nested PDF stream")
			}
			inStream, semantic = true, false
			content.Reset()
			continue
		}
		if line == "endstream" {
			if semantic {
				pages = append(pages, content.String())
			}
			inStream = false
			continue
		}
		const prefix = "/Span << /ActualText <"
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if !inStream {
			return "", fmt.Errorf("PDF semantic text outside a stream")
		}
		encoded, _, ok := strings.Cut(strings.TrimPrefix(line, prefix), ">")
		raw, err := hex.DecodeString(encoded)
		if !ok || err != nil || len(raw) < 2 || len(raw)%2 != 0 || raw[0] != 0xfe || raw[1] != 0xff {
			return "", fmt.Errorf("static PDF semantic encoding invalid")
		}
		units := make([]uint16, (len(raw)-2)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(raw[2+i*2:])
		}
		content.WriteString(string(utf16.Decode(units)))
		semantic = true
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if len(pages) == 0 || (inStream && semantic) {
		return "", fmt.Errorf("PDF has no complete semantic pages")
	}
	header := reporting.Banner + "Tenant: " + doc.TenantName + " (" + doc.TenantScope + ")" + "Absolute time: " + doc.AbsoluteFrom.UTC().Format(time.RFC3339Nano) + " to " + doc.AbsoluteTo.UTC().Format(time.RFC3339Nano)
	var text strings.Builder
	for i, page := range pages {
		footer := fmt.Sprintf("Page %d of %d", i+1, len(pages))
		if !strings.HasPrefix(page, header) || !strings.HasSuffix(page, footer) || len(page) < len(header)+len(footer) {
			return "", fmt.Errorf("PDF page %d has incomplete or conflicting tenant header/footer", i+1)
		}
		text.WriteString(page[len(header) : len(page)-len(footer)])
	}
	full := text.String()
	for key, value := range doc.Metrics {
		if !strings.Contains(full, key) || !strings.Contains(full, value) {
			return "", fmt.Errorf("static report metric text incomplete")
		}
	}
	for kind, values := range [][]string{doc.Provenance, doc.CoverageLimitations} {
		for index, value := range values {
			if !strings.Contains(full, value) {
				return "", fmt.Errorf("static report disclosure text incomplete: kind=%d index=%d", kind, index)
			}
		}
	}
	return full, nil
}

func assertStaticDocumentSemanticText(t *testing.T, body []byte, doc reporting.Document) {
	t.Helper()
	if _, err := staticDocumentSemanticText(body, doc); err != nil {
		t.Fatal(err)
	}
}

func TestStaticSemanticReaderRejoinsPagesWithoutDroppingDocumentText(t *testing.T) {
	doc := reporting.Document{TenantName: "Owned fixture", TenantScope: "tenant-a", Metrics: map[string]string{"metric-key": "metric-value"}, Provenance: []string{"provenance-field"}, CoverageLimitations: []string{"coverage-field"}}
	header := reporting.Banner + "Tenant: " + doc.TenantName + " (" + doc.TenantScope + ")" + "Absolute time: " + doc.AbsoluteFrom.UTC().Format(time.RFC3339Nano) + " to " + doc.AbsoluteTo.UTC().Format(time.RFC3339Nano)
	full := "metric-key: metric-value provenance-field coverage-field"
	parts := []string{full[:20], full[20:45], full[45:]}
	encode := func(pageHeader string, content []string, badFooter bool) []byte {
		var pdf strings.Builder
		span := func(value string) {
			pdf.WriteString("/Span << /ActualText <FEFF")
			for _, unit := range utf16.Encode([]rune(value)) {
				fmt.Fprintf(&pdf, "%04X", unit)
			}
			pdf.WriteString("> >> BDC\n")
		}
		for i, part := range content {
			pdf.WriteString("stream\n")
			span(pageHeader)
			span(part)
			page := i + 1
			if badFooter && i == 1 {
				page++
			}
			span(fmt.Sprintf("Page %d of %d", page, len(content)))
			pdf.WriteString("endstream\n")
		}
		return []byte(pdf.String())
	}
	if actual, err := staticDocumentSemanticText(encode(header, parts, false), doc); err != nil || actual != full {
		t.Fatal("reader did not preserve exact known content across page furniture", actual, err)
	}
	missing := append([]string(nil), parts...)
	missing[1] = missing[1][1:]
	for _, bad := range [][]byte{encode(header, missing, false), encode(header+"foreign", parts, false), encode(header, parts, true)} {
		if _, err := staticDocumentSemanticText(bad, doc); err == nil {
			t.Fatal("reader accepted missing original content or conflicting page furniture")
		}
	}
}
