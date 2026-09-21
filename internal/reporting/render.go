// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package reporting renders bounded, self-contained tenant report artifacts.
// It intentionally has no network client: rendering cannot phone home.
package reporting

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"sort"
	"strings"
	"time"
)

const Banner = "probectl · tenant-scoped report"

type Document struct {
	Title               string
	Preset              string
	TenantName          string
	TenantScope         string
	AbsoluteFrom        time.Time
	AbsoluteTo          time.Time
	GeneratedAt         time.Time
	GeneratedBy         string
	Provenance          []string
	RedactionState      string
	CoverageLimitations []string
	Metrics             map[string]string
}

// Validate rejects incomplete/honesty-ambiguous documents before any artifact
// is stored. In particular, relative time words never substitute for an exact
// interval and reports cannot omit provenance/redaction/coverage disclosures.
func (d Document) Validate() error {
	if strings.TrimSpace(d.Title) == "" || strings.TrimSpace(d.TenantName) == "" || strings.TrimSpace(d.TenantScope) == "" {
		return fmt.Errorf("title, tenant name, and tenant scope are required")
	}
	if d.AbsoluteFrom.IsZero() || !d.AbsoluteTo.After(d.AbsoluteFrom) || d.GeneratedAt.IsZero() {
		return fmt.Errorf("a valid absolute time interval and generation time are required")
	}
	if len(d.Provenance) == 0 || strings.TrimSpace(d.RedactionState) == "" || len(d.CoverageLimitations) == 0 {
		return fmt.Errorf("provenance, redaction state, and coverage limitations are required")
	}
	if len(d.Metrics) > 100 {
		return fmt.Errorf("report metric count exceeds 100")
	}
	return nil
}

func RenderCSV(d Document) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	rows := [][2]string{
		{"banner", Banner}, {"title", d.Title}, {"preset", d.Preset},
		{"tenant_name", d.TenantName}, {"tenant_scope", d.TenantScope},
		{"absolute_from", d.AbsoluteFrom.UTC().Format(time.RFC3339Nano)},
		{"absolute_to", d.AbsoluteTo.UTC().Format(time.RFC3339Nano)},
		{"generated_at", d.GeneratedAt.UTC().Format(time.RFC3339Nano)},
		{"generated_by", d.GeneratedBy},
		{"provenance", strings.Join(d.Provenance, " | ")},
		{"redaction_state", d.RedactionState},
		{"coverage_limitations", strings.Join(d.CoverageLimitations, " | ")},
	}
	for _, row := range rows {
		if err := w.Write([]string{row[0], row[1]}); err != nil {
			return nil, err
		}
	}
	if err := w.Write([]string{"metric", "exact_value"}); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(d.Metrics))
	for key := range d.Metrics {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := w.Write([]string{key, d.Metrics[key]}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RenderPDF emits a minimal standards-compliant one-page PDF using only the
// built-in Helvetica font. Avoiding a PDF dependency keeps air-gapped builds
// deterministic and adds no new outbound-capable code.
func RenderPDF(d Document) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	lines := []string{
		Banner, d.Title + " · " + d.Preset,
		"Tenant: " + d.TenantName + " (" + d.TenantScope + ")",
		"Absolute time: " + d.AbsoluteFrom.UTC().Format(time.RFC3339) + " to " + d.AbsoluteTo.UTC().Format(time.RFC3339),
		"Generated: " + d.GeneratedAt.UTC().Format(time.RFC3339) + " by " + d.GeneratedBy,
		"Provenance: " + strings.Join(d.Provenance, "; "),
		"Redaction: " + d.RedactionState,
		"Coverage: " + strings.Join(d.CoverageLimitations, "; "),
		"Exact values",
	}
	keys := make([]string, 0, len(d.Metrics))
	for key := range d.Metrics {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lines = append(lines, key+": "+d.Metrics[key])
	}
	if len(lines) > 42 {
		lines = append(lines[:41], "Additional exact values omitted by the one-page artifact cap")
	}
	var stream strings.Builder
	stream.WriteString("BT /F1 10 Tf 40 760 Td 13 TL\n")
	for i, line := range lines {
		if i > 0 {
			stream.WriteString("T*\n")
		}
		stream.WriteString("(")
		stream.WriteString(pdfText(line))
		stream.WriteString(") Tj\n")
	}
	stream.WriteString("ET\n")
	content := stream.String()
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	for i, object := range objects {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes(), nil
}

func pdfText(value string) string {
	var out strings.Builder
	for _, r := range value {
		switch r {
		case '\\', '(', ')':
			out.WriteByte('\\')
			out.WriteRune(r)
		default:
			if r >= 32 && r <= 126 {
				out.WriteRune(r)
			} else {
				out.WriteByte('?')
			}
		}
	}
	return out.String()
}
