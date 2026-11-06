// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportBodyStageStreamsCompleteCSV(t *testing.T) {
	d := testDocument()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(d.TenantScope))
	table := reportTable(d, []CSVColumn{{Name: "sequence", Numeric: true}, {Name: "tag:customer"}, {Name: "bytes", Numeric: true}, {Name: "delta", Numeric: true}}, nil)
	table.ExpectedRows = 500_000
	table.WalkRows = func(ctx context.Context, yield func([]string) error) error {
		for i := int64(0); i < 500_000; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := yield([]string{strconv.FormatInt(i, 10), "東京/موقع/🚀", strconv.FormatInt(9_007_199_254_740_993+i, 10), "-1.125"}); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	d.Tables = []CSVTable{table}
	var rendered CSVReceipt
	stage, receipt, err := StageBody(ctx, d.TenantScope, BodyStageLimitsForBytes(DefaultCSVLimits().Bytes), func(target io.Writer) error {
		var err error
		rendered, err = WriteCSV(ctx, target, d, DefaultCSVLimits())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stage.Close() }()
	if receipt.Bytes != rendered.Bytes || rendered.TableRows != 500_000 || receipt.Bytes <= 2<<20 || receipt.SHA256 == "" {
		t.Fatal("staged CSV did not retain full logical reach", receipt, rendered)
	}
	body, err := stage.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()
	reader := csv.NewReader(body)
	reader.FieldsPerRecord = -1
	for {
		row, err := reader.Read()
		if err != nil {
			t.Fatal("staged complete CSV header is missing", err)
		}
		if slices.Equal(row, []string{"sequence", "tag:customer", "bytes", "delta"}) {
			break
		}
	}
	for i := int64(0); i < 500_000; i++ {
		row, err := reader.Read()
		if err != nil || !slices.Equal(row, []string{strconv.FormatInt(i, 10), "東京/موقع/🚀", strconv.FormatInt(9_007_199_254_740_993+i, 10), "-1.125"}) {
			t.Fatal("staged CSV lost exact complete record", i, err)
		}
	}
	if _, err := reader.Read(); err != io.EOF {
		t.Fatal("staged CSV duplicated trailing records", err)
	}
	t.Logf("CSV staging: logical_rows=%d bytes=%d charged_allocation=%d complete_independent_stream_read", rendered.TableRows, receipt.Bytes, receipt.AllocatedBytes)
}

func TestReportBodyStageStreamsCompletePDF(t *testing.T) {
	d := testDocument()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(d.TenantScope))
	d.Metrics = map[string]string{"Unicode": "東京 العربية नमस्ते שָׁלוֹם ไทย e\u0301 🚀"}
	rows := make([][]string, 4000)
	for i := range rows {
		rows[i] = []string{fmt.Sprintf("staged-pdf-%04d", i), strconv.FormatInt(9_007_199_254_740_993+int64(i), 10)}
	}
	d.Tables = []CSVTable{reportTable(d, []CSVColumn{{Name: "identity"}, {Name: "exact_bytes", Numeric: true}}, rows)}
	var rendered PDFReceipt
	stage, receipt, err := StageBody(ctx, d.TenantScope, BodyStageLimitsForBytes(DefaultCSVLimits().Bytes), func(target io.Writer) error {
		var err error
		rendered, err = WritePDF(ctx, target, d, DefaultPDFLimits())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stage.Close() }()
	if receipt.Bytes != rendered.Bytes || rendered.TableRows != 4000 || receipt.Bytes <= 2<<20 || receipt.SHA256 == "" {
		t.Fatal("staged PDF did not retain full logical reach", receipt, rendered)
	}
	reader, err := stage.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	body, err := io.ReadAll(reader) // independent verifier memory, not production staging
	if err != nil || int64(len(body)) != receipt.Bytes {
		t.Fatal("staged PDF byte stream was incomplete", err)
	}
	text := pdfSemanticText(t, body)
	for _, row := range rows {
		for _, value := range row {
			if strings.Count(text, value) != 1 {
				t.Fatal("staged PDF lost or duplicated complete record", row[0])
			}
		}
	}
	for _, value := range []string{"東京", "العربية", "שָׁלוֹם", "नमस्ते", "e\u0301", "🚀"} {
		if !strings.Contains(text, value) {
			t.Fatal("staged PDF lost original Unicode", value)
		}
	}
	t.Logf("PDF staging: logical_rows=%d bytes=%d charged_allocation=%d complete_independent_semantic_read", rendered.TableRows, receipt.Bytes, receipt.AllocatedBytes)
}
