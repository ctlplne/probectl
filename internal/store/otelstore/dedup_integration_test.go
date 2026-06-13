// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package otelstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

// TestOtelDedupRealRoundTrip proves CORRECT-004 against a real ClickHouse:
// writing the SAME span and log batch twice (an at-least-once redelivery) must
// NOT permanently duplicate the rows — QuerySpans/QueryLogs read with FINAL and
// return each row once. Pre-fix (plain MergeTree, no FINAL) the second write
// produced permanent duplicates.
//
// Runs in the integration job (PROBECTL_OTELSTORE_URL points at the test
// ClickHouse); SkipOrFatal fails the build when PROBECTL_TEST_REQUIRE_SERVICES=1
// but CH is unavailable, so it can never pass by silently skipping in CI.
func TestOtelDedupRealRoundTrip(t *testing.T) {
	url := os.Getenv("PROBECTL_OTELSTORE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_OTELSTORE_URL not set — OTLP dedup gate runs in CI")
	}
	c, err := NewClickHouse(url, 0)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	tenant := fmt.Sprintf("itest-otel-%d", time.Now().UnixNano())
	now := time.Now().UTC()

	spans := []Span{{
		TenantID: tenant, TraceID: "aabbccdd", SpanID: "0011", Service: "checkout",
		Name: "GET /pay", Start: now.Add(-time.Minute), Duration: time.Millisecond, StatusCode: "ok",
	}}
	logs := []LogRecord{{
		TenantID: tenant, TS: now.Add(-time.Minute), SeverityNum: 9, SeverityText: "INFO",
		Service: "checkout", Body: "charge ok", TraceID: "aabbccdd", SpanID: "0011",
	}}

	for i := 0; i < 2; i++ { // write twice = redelivery
		if err := c.WriteSpans(ctx, spans); err != nil {
			t.Fatalf("write spans %d: %v", i, err)
		}
		if err := c.WriteLogs(ctx, logs); err != nil {
			t.Fatalf("write logs %d: %v", i, err)
		}
	}

	gotSpans, err := c.QuerySpans(ctx, tenant, SpanQuery{})
	if err != nil {
		t.Fatalf("query spans: %v", err)
	}
	if len(gotSpans) != 1 {
		t.Fatalf("redelivered span not deduped: got %d spans, want 1", len(gotSpans))
	}
	gotLogs, err := c.QueryLogs(ctx, tenant, LogQuery{})
	if err != nil {
		t.Fatalf("query logs: %v", err)
	}
	if len(gotLogs) != 1 {
		t.Fatalf("redelivered log not deduped: got %d logs, want 1", len(gotLogs))
	}
}
