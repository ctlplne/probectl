// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/fairness"
	prompb "github.com/ctlplne/probectl/internal/gen/prometheus/v1"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// TestDashboardReportGenerationRequiresMetricsWrite is the AUTHZ-28 regression.
// POST /v1/dashboard-reports PERSISTS an export artifact (auditFacetExport), yet
// the route was gated with metrics.read — so a viewer who holds only metrics.read
// could persist unbounded dashboard-report artifacts. The route now requires
// metrics.write; a principal that has metrics.read but NOT metrics.write must be
// refused at the authorization layer, before the handler ever runs (G7-5).
//
// Before the fix this FAILS: with metrics.write withheld the route still only
// demanded metrics.read, so the request reached the handler (and, on a real
// stack, returned 201 with a persisted artifact) instead of 403.
func TestDashboardReportGenerationRequiresMetricsWrite(t *testing.T) {
	handler := testServer(fakePinger{}).Handler()

	// A viewer: holds metrics.read, but metrics.write is withheld.
	req := httptest.NewRequest(http.MethodPost, "/v1/dashboard-reports",
		strings.NewReader(`{"dashboard_id":"11111111-1111-4111-8111-111111111111","format":"pdf"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(testWithholdPermissionsHeader, permMetricsWrite)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a metrics.read-only principal was allowed to persist a dashboard-report artifact: "+
			"status=%d body=%s (want 403)", rec.Code, rec.Body.String())
	}

	// Anti-vacuous control: with metrics.write present, authorization no longer
	// refuses. The request proceeds into the handler, where the empty body fails
	// validation (a non-403/401 status). This proves the 403 above is the
	// write-permission gate rather than a request the handler would reject anyway.
	req = httptest.NewRequest(http.MethodPost, "/v1/dashboard-reports", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("a principal holding metrics.write was refused at authorization (%d) — the gate is miswired",
			rec.Code)
	}
}

// remoteWriteBody builds a snappy-compressed Prometheus remote-write payload with
// a single one-sample series (its tenant label is overwritten server-side).
func remoteWriteBody(t *testing.T) []byte {
	t.Helper()
	wr := &prompb.WriteRequest{Timeseries: []*prompb.TimeSeries{{
		Labels: []*prompb.Label{
			{Name: "__name__", Value: "node_load1"},
			{Name: "instance", Value: "host1:9100"},
		},
		Samples: []*prompb.Sample{{Value: 0.7, Timestamp: time.Now().UnixMilli()}},
	}}}
	raw, err := proto.Marshal(wr)
	if err != nil {
		t.Fatalf("marshal remote write: %v", err)
	}
	return snappy.Encode(nil, raw)
}

func postRemoteWrite(t *testing.T, srv *Server, body []byte) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/prometheus/write", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}

// TestRemoteWriteFairnessAdmitsPerTenant is the TEN-04 (fairness half) regression.
// handlePromWrite wrote remote-write series into the shared in-memory TSDB with NO
// per-tenant fairness admission, so one tenant's remote-writes could evict another
// tenant's series across the shared byte wall with no per-tenant limit. The handler
// now mirrors the OTLP ingest contract (internal/pipeline/otlp.go): it charges the
// per-tenant series meter before the store write and sheds over-rate writes with 429.
//
// A tiny per-tenant policy (1 series/sec, 1-second burst = capacity 1) plus a frozen
// clock (so no tokens refill between calls) means the first write is admitted (204)
// and every subsequent write is shed (429). Before the fix every write returned 204,
// because the gate was never consulted — so this test FAILS before the fix.
func TestRemoteWriteFairnessAdmitsPerTenant(t *testing.T) {
	fixed := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	gate := fairness.NewGate(fairness.Policy{OTLPSeriesPerSec: 1, BurstSeconds: 1}, nil).
		WithNow(func() time.Time { return fixed })
	srv := testServer(fakePinger{}).WithTSDB(tsdb.NewMemory()).WithFairness(gate)

	body := remoteWriteBody(t)

	// First write: within the single-token budget — admitted.
	if code := postRemoteWrite(t, srv, body); code != http.StatusNoContent {
		t.Fatalf("first remote-write status = %d, want 204 (within the per-tenant budget)", code)
	}
	// Subsequent writes: the per-tenant series bucket is drained and cannot refill
	// (frozen clock), so each is shed with 429 rather than silently evicting a
	// neighbor's series across the shared TSDB wall.
	for i := 2; i <= 3; i++ {
		if code := postRemoteWrite(t, srv, body); code != http.StatusTooManyRequests {
			t.Fatalf("remote-write #%d status = %d, want 429 (per-tenant fairness limit exceeded)", i, code)
		}
	}
}
