// Package otelstore persists externally-ingested OTLP traces and logs
// (ARCH-001, Sprint 22) and serves their tenant-scoped queries. Two
// implementations share one contract: Memory (lightweight mode and tests)
// and ClickHouse (high-volume production, reached over the ClickHouse HTTP
// interface like flowstore — TLS in transit via an https URL).
//
// Tenancy: every row carries tenant_id; it leads the ClickHouse partition
// AND ORDER BY, and every query is tenant-scoped before anything else
// (CLAUDE.md §6/§7.1 — no data path that can return cross-tenant rows).
// Attributes are stored as a bounded, flattened key=value set — the OTLP
// resource/scope/point attribute tree is capped at ingest (cardinality
// stance, U-017).
package otelstore

import (
	"context"
	"time"
)

// Span is one stored trace span.
type Span struct {
	TenantID     string            `json:"tenant_id"`
	TraceID      string            `json:"trace_id"` // hex
	SpanID       string            `json:"span_id"`  // hex
	ParentSpanID string            `json:"parent_span_id,omitempty"`
	Name         string            `json:"name"`
	Kind         string            `json:"kind"` // server|client|producer|consumer|internal
	Service      string            `json:"service"`
	Start        time.Time         `json:"start"`
	Duration     time.Duration     `json:"duration"`
	StatusCode   string            `json:"status_code"` // unset|ok|error
	Attrs        map[string]string `json:"attrs,omitempty"`
}

// LogRecord is one stored log record.
type LogRecord struct {
	TenantID     string            `json:"tenant_id"`
	TS           time.Time         `json:"ts"`
	SeverityNum  int32             `json:"severity_num"`
	SeverityText string            `json:"severity_text,omitempty"`
	Service      string            `json:"service"`
	Body         string            `json:"body"`
	TraceID      string            `json:"trace_id,omitempty"`
	SpanID       string            `json:"span_id,omitempty"`
	Attrs        map[string]string `json:"attrs,omitempty"`
}

// SpanQuery filters a tenant's spans. Zero values mean "any".
type SpanQuery struct {
	TraceID string
	Service string
	Since   time.Time
	Until   time.Time
	Limit   int // <=0 => default 100, capped at 1000
}

// LogQuery filters a tenant's log records. Zero values mean "any".
type LogQuery struct {
	Service     string
	TraceID     string
	MinSeverity int32 // OTel severity number floor (0 = any)
	Since       time.Time
	Until       time.Time
	Limit       int // <=0 => default 100, capped at 1000
}

// Store persists and serves OTLP traces + logs for the query surface.
// Writes are batched by the pipeline consumers; queries are TENANT-SCOPED
// by construction (the tenant argument is the caller's authenticated
// tenant, never client input).
type Store interface {
	WriteSpans(ctx context.Context, spans []Span) error
	WriteLogs(ctx context.Context, recs []LogRecord) error
	QuerySpans(ctx context.Context, tenant string, q SpanQuery) ([]Span, error)
	QueryLogs(ctx context.Context, tenant string, q LogQuery) ([]LogRecord, error)
	Close() error
}

// clampLimit applies the shared query-limit policy.
func clampLimit(n int) int {
	switch {
	case n <= 0:
		return 100
	case n > 1000:
		return 1000
	default:
		return n
	}
}
