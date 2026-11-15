// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportPDFEmbedsCompleteMonthJSONAndKeepsTwoTenantScope(t *testing.T) {
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		t.Run(tenant, func(t *testing.T) {
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			// A complete 31-day population at one recorded execution per minute.
			// This is renderer input, not a claim of authenticated physical history.
			const executions = 31 * 24 * 60
			stage, receipt, err := StageBody(ctx, tenant, BodyStageLimitsForBytes(64<<20), func(w io.Writer) error {
				if _, err := io.WriteString(w, `{"originals":[`); err != nil {
					return err
				}
				for i := range executions {
					if i > 0 {
						if _, err := io.WriteString(w, ","); err != nil {
							return err
						}
					}
					if _, err := fmt.Fprintf(w, `{"execution":%d,"original":%q}`, i, strings.Repeat("0123456789abcdef", 64)); err != nil {
						return err
					}
				}
				_, err := io.WriteString(w, "]}")
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Close()
			d := testDocument()
			d.TenantScope = tenant
			table := reportTable(d, []CSVColumn{{Name: "ordinal", Numeric: true}}, [][]string{{"0"}, {"1"}})
			table.PDFFile = &PDFJSONFile{Name: "originals.json", Body: stage}
			d.Tables = []CSVTable{table}
			var pdf bytes.Buffer
			output, err := WritePDF(ctx, &pdf, d, DefaultPDFLimits())
			if err != nil {
				t.Fatal("complete month attachment was refused", err)
			}
			if output.TableRows != 2 || output.Bytes != int64(pdf.Len()) {
				t.Fatal("PDF receipt did not cover the whole file")
			}
			header := regexp.MustCompile(`/Type /EmbeddedFile /Subtype /application#2Fjson /Params << /Size ([0-9]+) >> /Length ([0-9]+) >>\nstream\n`).FindSubmatchIndex(pdf.Bytes())
			if header == nil {
				t.Fatal("complete JSON attachment is missing")
			}
			length, err := strconv.ParseInt(string(pdf.Bytes()[header[4]:header[5]]), 10, 64)
			if err != nil || length != receipt.Bytes || header[1]+int(length) > pdf.Len() {
				t.Fatal("embedded stream length changed", err)
			}
			embedded := pdf.Bytes()[header[1] : header[1]+int(length)]
			digest, err := crypto.HashReader(bytes.NewReader(embedded))
			if err != nil || fmt.Sprintf("%x", digest) != receipt.SHA256 || bytes.Count(embedded, []byte(`"execution":`)) != executions || !bytes.Contains(embedded, []byte(`"execution":44639`)) {
				t.Fatal("PDF shortened or changed a complete month", err)
			}
			if !bytes.Contains(pdf.Bytes(), []byte("/EmbeddedFiles")) || !strings.Contains(pdfSemanticText(t, pdf.Bytes()), receipt.SHA256) {
				t.Fatal("PDF lost the extractable file index or visible checksum")
			}
			// The same sealed body cannot be attached by the sibling tenant, even
			// when a caller changes all surrounding document/table labels.
			foreign := tenancy.WithTenant(t.Context(), tenancy.ID(tenant+"-foreign"))
			altered := d
			altered.TenantScope = tenant + "-foreign"
			altered.Tables = append([]CSVTable{}, d.Tables...)
			altered.Tables[0].TenantID = altered.TenantScope
			if _, err := WritePDF(foreign, io.Discard, altered, DefaultPDFLimits()); err == nil {
				t.Fatal("foreign sealed attachment crossed tenant scope")
			}
			short := DefaultPDFLimits()
			short.Bytes = receipt.Bytes - 1
			if _, err := WritePDF(ctx, io.Discard, d, short); err == nil {
				t.Fatal("complete output admission became a partial attachment")
			}
			if dir := os.Getenv("PROBECTL_PDF_PROOF_DIR"); dir != "" {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "month-"+tenant+".pdf"), pdf.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				metadata, err := json.Marshal(map[string]any{"sha256": receipt.SHA256, "bytes": receipt.Bytes, "executions": executions, "pages": output.Pages})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "month-"+tenant+".json"), metadata, 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("complete month JSON executions=%d bytes=%d PDF bytes=%d pages=%d", executions, receipt.Bytes, output.Bytes, output.Pages)
		})
	}
}

func TestReportPDFEmbeddedFilesRefuseUnsafeNamesMissingBodyAndRowLoss(t *testing.T) {
	d := testDocument()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(d.TenantScope))
	body, _, err := StageBody(ctx, d.TenantScope, BodyStageLimitsForBytes(1<<20), func(w io.Writer) error { _, err := io.WriteString(w, `{"complete":true}`); return err })
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	for _, name := range []string{"../originals.json", "originals.js", "file:///originals.json", "originals).json", "originals\n.json", ".json"} {
		table := reportTable(d, []CSVColumn{{Name: "value"}}, [][]string{{"complete"}})
		table.PDFFile = &PDFJSONFile{Name: name, Body: body}
		d.Tables = []CSVTable{table}
		if _, err := WritePDF(ctx, io.Discard, d, DefaultPDFLimits()); err == nil {
			t.Fatal("unsafe PDF filename accepted", name)
		}
	}
	table := reportTable(d, []CSVColumn{{Name: "value"}}, [][]string{{"complete"}})
	table.PDFFile = &PDFJSONFile{Name: "originals.json", Body: body}
	d.Tables = []CSVTable{table}
	d.Tables[0].ExpectedRows++
	if _, err := WritePDF(ctx, io.Discard, d, DefaultPDFLimits()); err == nil {
		t.Fatal("embedded attachment masked incomplete logical table")
	}
	d.Tables[0].ExpectedRows--
	d.Tables[0].PDFFile = &PDFJSONFile{Name: "originals.json"}
	if _, err := WritePDF(ctx, io.Discard, d, DefaultPDFLimits()); err == nil {
		t.Fatal("missing complete body accepted")
	}
}
