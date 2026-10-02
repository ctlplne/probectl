// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpointstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/store/chclient"
)

// countingSink tallies lines and bytes without buffering the stream, so the
// test's own memory stays bounded while the export writes hundreds of MiB.
type countingSink struct{ lines, bytes int64 }

func (s *countingSink) Write(p []byte) (int, error) {
	s.bytes += int64(len(p))
	s.lines += int64(bytes.Count(p, []byte("\n")))
	return len(p), nil
}

// exportLine is the JSONEachRow row shape the export SELECT returns.
type exportLine struct {
	TenantID       string `json:"tenant_id"`
	AgentID        string `json:"agent_id"`
	SignalType     string `json:"signal_type"`
	SignalKey      string `json:"signal_key"`
	Target         string `json:"target"`
	Success        bool   `json:"success"`
	Error          string `json:"error"`
	MetricsJSON    string `json:"metrics_json"`
	AttributesJSON string `json:"attributes_json"`
	ObservedAt     string `json:"observed_at"`
}

// isExportQuery recognizes the ExportTenant SELECT (attributes_json is unique to
// it among the store's reads) so the fake server streams the oversized body only
// for the export, answering migrations/ledger/counts with a bare 200.
func isExportQuery(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.URL.Query().Get("query"), "attributes_json")
}

// TestExportTenantStreamsPast64MiB is the GAP-05 acceptance test on the LIVE
// public path (ExportTenant → stream), without ClickHouse: the fake data plane
// streams a single tenant's endpoint history far larger than
// chclient.MaxResponseBytes (64 MiB). Pre-fix, ExportTenant read the whole body
// through chclient.ReadResponseBody and aborted with ErrResponseTooLarge (the
// "exceeds 67108864-byte limit" error); post-fix it decodes JSONEachRow
// line-by-line and completes with the exact row count, the control-plane never
// buffering the whole plane.
func TestExportTenantStreamsPast64MiB(t *testing.T) {
	const rowsN = 70_000 // ~84 MiB of JSONEachRow, comfortably past the 64 MiB cap
	tenant := "tenant-export-big"

	blob := strings.Repeat("x", 1000)
	rowBytes, err := json.Marshal(exportLine{
		TenantID: tenant, AgentID: "agent-1", SignalType: "endpoint.wifi",
		SignalKey: "k", Target: "ssid", Success: true,
		AttributesJSON: `{"blob":"` + blob + `"}`,
		ObservedAt:     "2024-01-02 03:04:05.000000",
	})
	if err != nil {
		t.Fatalf("marshal row: %v", err)
	}
	rowBytes = append(rowBytes, '\n')

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isExportQuery(r) {
			w.WriteHeader(http.StatusOK) // migrations / ledger / counts
			return
		}
		w.WriteHeader(http.StatusOK)
		for i := 0; i < rowsN; i++ {
			if _, err := w.Write(rowBytes); err != nil {
				return // client stopped early (the pre-fix bounded read closes here)
			}
		}
	}))
	defer srv.Close()

	store, err := NewClickHouseWithClient(srv.URL, 0, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sink := &countingSink{}
	n, err := store.ExportTenant(context.Background(), tenant, sink)
	if err != nil {
		t.Fatalf("ExportTenant must stream past the 64 MiB cap, got error: %v", err)
	}
	if n != rowsN {
		t.Fatalf("row count = %d, want %d", n, rowsN)
	}
	if sink.lines != rowsN {
		t.Fatalf("emitted lines = %d, want %d", sink.lines, rowsN)
	}
	if sink.bytes <= chclient.MaxResponseBytes {
		t.Fatalf("export wrote %d bytes, expected it to exceed the %d-byte whole-response cap", sink.bytes, chclient.MaxResponseBytes)
	}
}

// TestExportTenantRejectsOversizedRow proves the whole-response cap is replaced
// by a PER-ROW bound that still fails closed: a single row larger than
// maxExportRowBytes aborts the stream rather than being buffered without limit.
func TestExportTenantRejectsOversizedRow(t *testing.T) {
	tenant := "tenant-fat-row"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isExportQuery(r) {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		// One row whose JSON exceeds maxExportRowBytes, with no newline until the
		// end — the bounded scanner must stop it.
		row, _ := json.Marshal(exportLine{
			TenantID: tenant, AgentID: "a", SignalType: "endpoint.wifi",
			AttributesJSON: `{"blob":"` + strings.Repeat("y", maxExportRowBytes) + `"}`,
			ObservedAt:     "2024-01-02 03:04:05.000000",
		})
		_, _ = w.Write(append(row, '\n'))
	}))
	defer srv.Close()

	store, err := NewClickHouseWithClient(srv.URL, 0, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, err = store.ExportTenant(context.Background(), tenant, io.Discard)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("exceeds %d-byte limit", maxExportRowBytes)) {
		t.Fatalf("oversized row must fail closed on the per-row bound, got %v", err)
	}
}

// TestExportTenantStopsOnForeignTenant keeps the storage-layer tenant check
// (docs/guardrails.md G7-1) on the streaming path: a row carrying another
// tenant's id aborts the export instead of leaking across the boundary.
func TestExportTenantStopsOnForeignTenant(t *testing.T) {
	tenant := "tenant-self"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isExportQuery(r) {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		mine, _ := json.Marshal(exportLine{TenantID: tenant, AgentID: "a", SignalType: "t", ObservedAt: "2024-01-02 03:04:05.000000"})
		other, _ := json.Marshal(exportLine{TenantID: "tenant-OTHER", AgentID: "a", SignalType: "t", ObservedAt: "2024-01-02 03:04:05.000000"})
		_, _ = w.Write(append(mine, '\n'))
		_, _ = w.Write(append(other, '\n'))
	}))
	defer srv.Close()

	store, err := NewClickHouseWithClient(srv.URL, 0, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	n, err := store.ExportTenant(context.Background(), tenant, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "export boundary returned tenant") {
		t.Fatalf("foreign tenant row must fail closed, got n=%d err=%v", n, err)
	}
	if n != 1 {
		t.Fatalf("expected the one in-tenant row emitted before the boundary abort, got %d", n)
	}
}
