// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package otelstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestOtelSubjectEraseAndExportAreExact is the TEN-05 regression against a real
// ClickHouse. The old span/log predicates used positionCaseInsensitive over the
// raw attrs JSON blob, so subject "10.0.0.1" also matched spans/logs whose
// attribute value was "10.0.0.10" or "110.0.0.1" (the subject is a substring of
// both). EraseSubject therefore destroyed, and ExportSubject disclosed, three
// subjects' rows for one DSAR request. The fix matches structured columns by
// equality and attrs by EXACT attribute VALUE, so only the "10.0.0.1" rows match.
//
// Runs in the integration job (PROBECTL_OTELSTORE_URL points at the test
// ClickHouse); SkipOrFatal fails the build when services are mandatory in CI.
func TestOtelSubjectEraseAndExportAreExact(t *testing.T) {
	url := os.Getenv("PROBECTL_OTELSTORE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_OTELSTORE_URL not set — TEN-05 exact-match gate runs in CI")
	}
	c, err := NewClickHouseWithClient(url, 0, nil)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	tenant := fmt.Sprintf("itest-ten05-otel-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)
	t.Cleanup(func() { _, _, _ = c.EraseTenant(ctx, tenant) })

	// Three spans whose client.ip attribute values are neighboring addresses.
	if err := c.WriteSpans(ctx, []Span{
		{TenantID: tenant, TraceID: "trace-exact", SpanID: "s1", Service: "api", Start: now, Attrs: map[string]string{"client.ip": "10.0.0.1"}},
		{TenantID: tenant, TraceID: "trace-near", SpanID: "s2", Service: "api", Start: now, Attrs: map[string]string{"client.ip": "10.0.0.10"}},
		{TenantID: tenant, TraceID: "trace-wide", SpanID: "s3", Service: "api", Start: now, Attrs: map[string]string{"client.ip": "110.0.0.1"}},
	}); err != nil {
		t.Fatalf("write spans: %v", err)
	}
	// Two logs with neighboring peer attribute values.
	if err := c.WriteLogs(ctx, []LogRecord{
		{TenantID: tenant, TS: now, Service: "api", Body: "connected", Attrs: map[string]string{"peer": "10.0.0.1"}},
		{TenantID: tenant, TS: now, Service: "api", Body: "connected", Attrs: map[string]string{"peer": "10.0.0.10"}},
	}); err != nil {
		t.Fatalf("write logs: %v", err)
	}

	// Export for the exact subject must return only the "10.0.0.1" span + log.
	var spansBuf, logsBuf bytes.Buffer
	spans, logs, err := c.ExportSubject(ctx, tenant, "10.0.0.1", &spansBuf, &logsBuf)
	if err != nil {
		t.Fatalf("ExportSubject: %v", err)
	}
	if spans != 1 || logs != 1 {
		t.Fatalf("ExportSubject(10.0.0.1) = spans=%d logs=%d, want 1/1 (substring over-match returns 3/2)", spans, logs)
	}
	if body := spansBuf.String(); !bytes.Contains([]byte(body), []byte("10.0.0.1")) ||
		bytes.Contains([]byte(body), []byte("10.0.0.10")) || bytes.Contains([]byte(body), []byte("110.0.0.1")) {
		t.Fatalf("span export leaked a neighboring subject: %s", body)
	}

	// Erase for the exact subject must remove exactly the 1 span + 1 log.
	deleted, remaining, err := c.EraseSubject(ctx, tenant, "10.0.0.1")
	if err != nil {
		t.Fatalf("EraseSubject: %v", err)
	}
	if deleted != 2 || remaining != 0 {
		t.Fatalf("EraseSubject(10.0.0.1) = deleted=%d remaining=%d, want 2/0 (substring over-match deletes 5)", deleted, remaining)
	}

	// The neighbors must survive: the subject is gone but 10.0.0.10 is still there.
	var sB, lB bytes.Buffer
	goneSpans, goneLogs, err := c.ExportSubject(ctx, tenant, "10.0.0.1", &sB, &lB)
	if err != nil {
		t.Fatalf("ExportSubject after erase: %v", err)
	}
	if goneSpans != 0 || goneLogs != 0 {
		t.Fatalf("subject survived erase: spans=%d logs=%d", goneSpans, goneLogs)
	}
	var sN, lN bytes.Buffer
	nearSpans, nearLogs, err := c.ExportSubject(ctx, tenant, "10.0.0.10", &sN, &lN)
	if err != nil {
		t.Fatalf("ExportSubject neighbor: %v", err)
	}
	if nearSpans != 1 || nearLogs != 1 {
		t.Fatalf("CROSS-SUBJECT LOSS: neighbor 10.0.0.10 erased with the subject (spans=%d logs=%d, want 1/1)", nearSpans, nearLogs)
	}
}
