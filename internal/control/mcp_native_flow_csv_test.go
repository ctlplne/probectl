// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
)

func nativeCSVFixture(t *testing.T, columns []string, records [][]string) *preparedFlowCSV {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "native-csv-*")
	if err != nil {
		t.Fatal(err)
	}
	p := &preparedFlowCSV{file: file, header: flowsnapshot.Header{SnapshotID: "owned-result", SelectedRows: len(records)}, digest: "source-provenance"}
	t.Cleanup(p.close)
	w := csv.NewWriter(file)
	if err := w.Write(columns); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteAll(records); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	p.size = info.Size()
	return p
}

func TestNativeCSVPagesReconstructWholeMultilineCellsAndExactMetrics(t *testing.T) {
	columns := []string{"record_type", "label", "bytes:total"}
	records := [][]string{{"detail", "雪,\"quoted\"\r\nline", "9007199254740993"}, {"detail", "'=formula", "9007199254740994"}, {"other", "", "10"}, {"totals", "", "18014398509481997"}}
	p := nativeCSVFixture(t, columns, records)
	var reconstructed [][]string
	for offset := 0; ; {
		if _, err := p.file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		page, err := nativeFlowCSVRecords(t.Context(), p, mcp.NativeFlowCSVInput{RecordOffset: offset, PageSize: 2})
		if err != nil || page.TotalRecords != len(records) || !reflect.DeepEqual(page.Columns, columns) || page.RecordOffset != offset || page.SourceSHA256 != p.digest || page.SourceBytes != p.size {
			t.Fatal("CSV page changed complete source metadata", err)
		}
		reconstructed = append(reconstructed, page.Records...)
		if page.NextRecord == nil {
			break
		}
		offset = *page.NextRecord
	}
	if !reflect.DeepEqual(reconstructed, records) {
		t.Fatal("CSV paging split, omitted or changed a cell")
	}
	var encoded bytes.Buffer
	w := csv.NewWriter(&encoded)
	if err := w.Write(columns); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteAll(reconstructed); err != nil {
		t.Fatal(err)
	}
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	original, err := io.ReadAll(p.file)
	if err != nil || !bytes.Equal(original, encoded.Bytes()) {
		t.Fatal("MCP records do not reconstruct the complete source CSV")
	}
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeFlowCSVRecords(t.Context(), p, mcp.NativeFlowCSVInput{RecordOffset: 5, PageSize: 2}); err == nil {
		t.Fatal("offset beyond complete CSV accepted")
	}
}

func TestNativeCSVResourcePagingStopsOnlyBetweenCompleteRecords(t *testing.T) {
	value := strings.Repeat("雪", mcp.DefaultNativeFlowRenderBudget().CSVPageBytes/6)
	record := []string{"detail", value}
	p := nativeCSVFixture(t, []string{"type", "label"}, [][]string{record, record, record, record})
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	page, err := nativeFlowCSVRecords(t.Context(), p, mcp.NativeFlowCSVInput{PageSize: 5000})
	if err != nil || len(page.Records) != 1 || page.TotalRecords != 4 || page.NextRecord == nil || *page.NextRecord != 1 || page.Records[0][1] != value {
		t.Fatal("resource budget truncated a complete record or lost continuation", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeFlowCSVRecords(ctx, p, mcp.NativeFlowCSVInput{PageSize: 2}); err == nil {
		t.Fatal("canceled preparation published CSV")
	}
}

func TestNativeCSVConfiguredBudgetPreservesCompleteContinuation(t *testing.T) {
	record := []string{"detail", "雪,\"quoted\"\nline", "9007199254740993"}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	p := nativeCSVFixture(t, []string{"kind", "label", "bytes:total"}, [][]string{record, record, record})
	budget := mcp.DefaultNativeFlowRenderBudget()
	budget.CSVPageBytes = len(encoded)
	var records [][]string
	for offset := 0; ; {
		if _, err := p.file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		page, err := nativeFlowCSVRecordsWithBudget(t.Context(), p, mcp.NativeFlowCSVInput{RecordOffset: offset, PageSize: 5000}, budget)
		if err != nil || len(page.Records) != 1 || page.TotalRecords != 3 || !reflect.DeepEqual(page.Records[0], record) {
			t.Fatal("configured transport budget lost a complete record", err)
		}
		records = append(records, page.Records...)
		if page.NextRecord == nil {
			break
		}
		offset = *page.NextRecord
	}
	if len(records) != 3 {
		t.Fatal("configured paging narrowed export reach")
	}
	budget.CSVPageBytes--
	if _, err := p.file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	page, err := nativeFlowCSVRecordsWithBudget(t.Context(), p, mcp.NativeFlowCSVInput{PageSize: 5000}, budget)
	if !errors.Is(err, flowsnapshot.ErrBudget) || len(page.Records) != 0 {
		t.Fatal("oversized complete record returned partial content", err)
	}
}

func TestNativeCSVPreservesCRLFAtReadBoundaries(t *testing.T) {
	records := [][]string{{"kind", "label", "exact"}, {"detail", "雪,\"quoted\"\r\nline", "9007199254740993"}, {"detail", "\r\r\n\t=literal", "9007199254740994"}, {"detail", strings.Repeat("🌐", 24000) + "\r\nlast\r", "0"}, {"totals", "", "18014398509481997"}}
	var encoded bytes.Buffer
	writer := csv.NewWriter(&encoded)
	if err := writer.WriteAll(records); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), encoded.Bytes()...)
	for _, oneByte := range []bool{false, true} {
		var source io.Reader = bytes.NewReader(original)
		if oneByte {
			source = iotest.OneByteReader(source)
		}
		var preserved io.Reader = &nativeCSVCRLFReader{source: bufio.NewReader(source)}
		if oneByte {
			preserved = iotest.OneByteReader(preserved)
		}
		got, err := csv.NewReader(preserved).ReadAll()
		if err != nil || !reflect.DeepEqual(got, records) || !bytes.Equal(original, encoded.Bytes()) {
			t.Fatalf("native CSV changed full cells or original source at oneByte=%v: %v", oneByte, err)
		}
	}
}
