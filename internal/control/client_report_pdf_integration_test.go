// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/reporting"
)

// Read the actual downloaded PDF's complete semantic stream independently of
// the renderer's encoder. Strip only the exact repeated page-header prefix
// and numbered footer. Every cell, including an envelope across pages, remains.
// Independent Poppler extraction/ink checks remain a separate CI requirement.
func monthlyPDFBodyText(t *testing.T, body []byte) string {
	t.Helper()
	var result strings.Builder
	var header []string
	pages, total := 0, 0
	for _, stream := range regexp.MustCompile(`(?s)stream\n(.*?)endstream`).FindAllSubmatch(body, -1) {
		var spans []string
		for _, match := range regexp.MustCompile(`/ActualText <([0-9A-F]+)>`).FindAllSubmatch(stream[1], -1) {
			raw, err := hex.DecodeString(string(match[1]))
			if err != nil || len(raw) < 2 || len(raw)%2 != 0 || !bytes.Equal(raw[:2], []byte{0xfe, 0xff}) {
				t.Fatal("PDF has invalid semantic text")
			}
			units := make([]uint16, (len(raw)-2)/2)
			for i := range units {
				units[i] = binary.BigEndian.Uint16(raw[2+i*2 : 4+i*2])
			}
			spans = append(spans, string(utf16.Decode(units)))
		}
		if len(spans) == 0 {
			continue
		}
		if header == nil {
			for index, text := range spans {
				if text == "Monthly client pack - operator" {
					header = append([]string{}, spans[:index]...)
					break
				}
			}
			if len(header) == 0 {
				t.Fatal("PDF monthly body is missing after its tenant header")
			}
		}
		if len(spans) < len(header) {
			t.Fatal("PDF page lost its tenant header")
		}
		for index, text := range header {
			if spans[index] != text {
				t.Fatal("PDF page header changed tenant or interval")
			}
		}
		footer := regexp.MustCompile(`^Page ([1-9][0-9]*) of ([1-9][0-9]*)$`).FindStringSubmatch(spans[len(spans)-1])
		if len(footer) != 3 {
			t.Fatal("PDF lost its final page counter")
		}
		page, err := strconv.Atoi(footer[1])
		if err != nil {
			t.Fatal(err)
		}
		count, err := strconv.Atoi(footer[2])
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if page != pages || (total != 0 && total != count) {
			t.Fatal("PDF page sequence is incomplete")
		}
		total = count
		for _, text := range spans[len(header) : len(spans)-1] {
			result.WriteString(text)
		}
	}
	if result.Len() == 0 || pages != total {
		t.Fatal("downloaded PDF has no complete semantic body")
	}
	return result.String()
}

func proveServedMonthlyPDF(ctx context.Context, t *testing.T, body []byte, tables []reporting.CSVTable, tenant, foreign, incident, public, secret string) {
	t.Helper()
	text := monthlyPDFBodyText(t, body)
	if strings.Contains(text, foreign) || strings.Contains(text, secret) {
		t.Fatal("served monthly PDF exposed foreign or secret data")
	}
	if strings.Count(text, "Table identity: ") != len(tables) || len(tables) != 6 {
		t.Fatal("served monthly PDF omitted or duplicated a source section")
	}
	for index, table := range tables {
		_, section, ok := strings.Cut(text, "Table identity: "+table.ID)
		if !ok {
			t.Fatal("served monthly PDF lost section", table.ID)
		}
		if index+1 < len(tables) {
			section, _, _ = strings.Cut(section, "Table: ")
		}
		if !strings.Contains(section, "Logical rows: "+strconv.FormatInt(table.ExpectedRows, 10)) {
			t.Fatal("served monthly PDF changed row metadata", table.ID)
		}
		rowOffsets := regexp.MustCompile(`Row [0-9]+tenant_id:`).FindAllStringIndex(section, -1)
		if int64(len(rowOffsets)) != table.ExpectedRows {
			t.Fatal("served monthly PDF omitted or duplicated logical rows", table.ID)
		}
		sourceRow := 0
		if err := table.WalkRows(ctx, func(row []string) error {
			if sourceRow >= len(rowOffsets) {
				t.Fatal("PDF has fewer rows than the complete source")
			}
			end := len(section)
			if sourceRow+1 < len(rowOffsets) {
				end = rowOffsets[sourceRow+1][0]
			}
			record := section[rowOffsets[sourceRow][0]:end]
			if !strings.HasPrefix(record, "Row "+strconv.Itoa(sourceRow+1)+"tenant_id: ") {
				t.Fatal("PDF row sequence changed", table.ID)
			}
			for col, value := range row {
				column := table.Columns[col]
				if strings.Count(record, column.Name+": ") != 1 {
					t.Fatal("served monthly PDF omitted or duplicated a captured column", table.ID, column.Name)
				}
				identity := strings.HasSuffix(column.Name, "_id") && column.Name != "package_id" && column.Name != "evidence_package_id"
				if column.Numeric || identity || strings.HasSuffix(column.Name, "_numerator") || strings.HasSuffix(column.Name, "_denominator") {
					want := column.Name + ": " + value
					exact := strings.HasSuffix(record, want)
					if col+1 < len(table.Columns) {
						want += table.Columns[col+1].Name + ": "
						exact = strings.Contains(record, want)
					}
					if !exact {
						t.Fatal("served monthly PDF changed an exact source identity or number", table.ID, column.Name)
					}
				}
			}
			sourceRow++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if int64(sourceRow) != table.ExpectedRows {
			t.Fatal("PDF source ended before its complete row count")
		}
	}
	_, index, found := strings.Cut(text, "Table identity: client-evidence")
	if !found {
		t.Fatal("served monthly PDF lost its signed evidence table")
	}
	index, _, _ = strings.Cut(index, "Table: ")
	_, encoded, found := strings.Cut(index, "signed_package_base64: ")
	if !found || strings.Contains(encoded, "signed_package_base64: ") {
		t.Fatal("served monthly PDF lost complete signed index")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal("served monthly PDF changed complete signed envelope", err)
	}
	manifest, err := evidence.Verify(raw)
	if err != nil || manifest.Incident.ID != incident || manifest.TenantScopeDigest != "sha256:"+hex.EncodeToString(crypto.Hash([]byte(tenant))) {
		t.Fatal("served monthly PDF signed index failed offline tenant verification", err)
	}
	var signed evidence.Package
	if err := json.Unmarshal(raw, &signed); err != nil || signed.Signing.PublicKey != public {
		t.Fatal("served monthly PDF changed the trusted signing identity", err)
	}
	if !strings.Contains(text, "package_id: "+manifest.PackageID) || !strings.Contains(text, "package_sha256: "+hex.EncodeToString(crypto.Hash(raw))) {
		t.Fatal("served monthly PDF signed index metadata disagrees with its envelope")
	}
}
