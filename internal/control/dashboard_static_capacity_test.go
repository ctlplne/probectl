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
	assertStaticDocumentSemanticText(t, reference, doc)
	t.Logf("validated static capacity: input_bytes=%d exact_metrics=%d provenance_entries=%d coverage_entries=%d complete_pdf_bytes=%d", len(encoded), len(doc.Metrics), len(doc.Provenance), len(doc.CoverageLimitations), receipt.Bytes)
	actual, media, err := renderDashboardReport(ctx, "pdf", doc)
	if err != nil {
		t.Fatalf("static renderer refused complete validated document: complete_pdf_bytes=%d error=%v", receipt.Bytes, err)
	}
	if media != "application/pdf" {
		t.Fatal("static renderer changed media type")
	}
	assertStaticDocumentSemanticText(t, actual, doc)
}

// Decode the standard UTF-16 ActualText spans independently of the renderer.
// Every unique original field must survive; a smaller cropped output cannot pass.
func assertStaticDocumentSemanticText(t *testing.T, body []byte, doc reporting.Document) {
	t.Helper()
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var text strings.Builder
	for scanner.Scan() {
		const prefix = "/Span << /ActualText <"
		line := scanner.Text()
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		encoded, _, ok := strings.Cut(strings.TrimPrefix(line, prefix), ">")
		raw, err := hex.DecodeString(encoded)
		if !ok || err != nil || len(raw) < 2 || len(raw)%2 != 0 || raw[0] != 0xfe || raw[1] != 0xff {
			t.Fatal("static PDF semantic encoding invalid")
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
	full := text.String()
	for key, value := range doc.Metrics {
		if !strings.Contains(full, key) || !strings.Contains(full, value) {
			t.Fatal("static report metric text incomplete")
		}
	}
	for _, values := range [][]string{doc.Provenance, doc.CoverageLimitations} {
		for _, value := range values {
			if !strings.Contains(full, value) {
				t.Fatal("static report disclosure text incomplete")
			}
		}
	}
}
