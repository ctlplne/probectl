// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package endpointstore

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestEndpointExportStreamsLargeHistoryClickHouse is the GAP-05 acceptance test
// against real ClickHouse: it writes one tenant well over 256 MiB of endpoint
// events and proves ExportTenant streams the whole history with the exact row
// count while the control-plane heap stays bounded. Pre-fix the export read the
// response whole through chclient.ReadResponseBody and aborted with the
// "exceeds 67108864-byte limit" error; post-fix it decodes JSONEachRow
// line-by-line and completes. Needs ClickHouse (PROBECTL_TEST_CLICKHOUSE_URL).
func TestEndpointExportStreamsLargeHistoryClickHouse(t *testing.T) {
	rawURL := os.Getenv("PROBECTL_TEST_CLICKHOUSE_URL")
	if rawURL == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_CLICKHOUSE_URL not set — endpoint export streaming integration needs ClickHouse")
	}

	const (
		blobBytes  = 64 << 10 // ~64 KiB attributes per event
		totalRows  = 4352     // 4352 * 64 KiB ≈ 272 MiB, comfortably past 256 MiB
		batchRows  = 64       // ~4 MiB per insert POST
		heapBudget = 64 << 20 // export must not grow live heap by the plane size
	)

	store, err := NewClickHouseWithClient(rawURL, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	tenant := "endpoint-export-" + time.Now().UTC().Format("20060102150405.000000000")
	defer func() { _, _ = store.DeleteTenant(ctx, tenant) }()

	blob := strings.Repeat("x", blobBytes)
	base := time.Now().UTC().Add(-time.Duration(totalRows) * time.Millisecond)
	for start := 0; start < totalRows; start += batchRows {
		end := start + batchRows
		if end > totalRows {
			end = totalRows
		}
		batch := make([]Event, 0, end-start)
		for i := start; i < end; i++ {
			batch = append(batch, Event{
				TenantID:   tenant,
				AgentID:    "agent-1",
				Type:       "endpoint.wifi",
				SignalKey:  fmt.Sprintf("k-%06d", i), // unique → distinct event_id, no FINAL dedup
				Target:     "ssid",
				ObservedAt: base.Add(time.Duration(i) * time.Millisecond),
				Attributes: map[string]string{"blob": blob},
			})
		}
		if err := store.Insert(ctx, batch); err != nil {
			t.Fatalf("insert batch [%d,%d): %v", start, end, err)
		}
	}

	sink := &countingSink{}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	n, err := store.ExportTenant(ctx, tenant, sink)
	if err != nil {
		t.Fatalf("ExportTenant must stream the >256 MiB history, got error: %v", err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if n != totalRows {
		t.Fatalf("exported row count = %d, want %d", n, totalRows)
	}
	if sink.lines != totalRows {
		t.Fatalf("emitted JSONL lines = %d, want %d", sink.lines, totalRows)
	}
	if sink.bytes < 256<<20 {
		t.Fatalf("export wrote %d bytes, expected >= 256 MiB of history", sink.bytes)
	}
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > heapBudget {
		t.Fatalf("live heap grew %d bytes exporting a %d-byte plane; stream must not buffer it whole", grew, sink.bytes)
	}
}
