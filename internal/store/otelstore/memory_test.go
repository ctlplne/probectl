package otelstore

import (
	"context"
	"testing"
	"time"
)

func TestMemorySpanAndLogQueriesScopedAndFiltered(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	base := time.Now().UTC()

	if err := m.WriteSpans(ctx, []Span{
		{TenantID: "t1", TraceID: "aa", SpanID: "01", Service: "checkout", Name: "GET /a", Start: base},
		{TenantID: "t1", TraceID: "bb", SpanID: "02", Service: "cart", Name: "GET /b", Start: base.Add(time.Second)},
		{TenantID: "t2", TraceID: "cc", SpanID: "03", Service: "checkout", Name: "GET /c", Start: base},
		{TraceID: "dd", SpanID: "04", Service: "orphan", Start: base}, // no tenant: dropped
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteLogs(ctx, []LogRecord{
		{TenantID: "t1", TS: base, SeverityNum: 9, Service: "checkout", Body: "info line"},
		{TenantID: "t1", TS: base.Add(time.Second), SeverityNum: 17, Service: "checkout", Body: "error line", TraceID: "aa"},
		{TenantID: "t2", TS: base, SeverityNum: 21, Service: "checkout", Body: "other tenant"},
	}); err != nil {
		t.Fatal(err)
	}

	// Tenant scoping is absolute.
	spans, _ := m.QuerySpans(ctx, "t1", SpanQuery{})
	if len(spans) != 2 {
		t.Fatalf("t1 must see exactly its 2 spans: %+v", spans)
	}
	for _, s := range spans {
		if s.TenantID != "t1" {
			t.Fatalf("cross-tenant span: %+v", s)
		}
	}
	if got, _ := m.QuerySpans(ctx, "t3", SpanQuery{}); len(got) != 0 {
		t.Fatal("unknown tenant must see nothing")
	}

	// Filters: service, trace, time, severity floor; newest first.
	if got, _ := m.QuerySpans(ctx, "t1", SpanQuery{Service: "cart"}); len(got) != 1 || got[0].TraceID != "bb" {
		t.Fatalf("service filter: %+v", got)
	}
	if got, _ := m.QuerySpans(ctx, "t1", SpanQuery{Since: base.Add(500 * time.Millisecond)}); len(got) != 1 || got[0].TraceID != "bb" {
		t.Fatalf("since filter: %+v", got)
	}
	logs, _ := m.QueryLogs(ctx, "t1", LogQuery{MinSeverity: 17})
	if len(logs) != 1 || logs[0].Body != "error line" {
		t.Fatalf("severity floor: %+v", logs)
	}
	if got, _ := m.QueryLogs(ctx, "t1", LogQuery{TraceID: "aa"}); len(got) != 1 || got[0].Body != "error line" {
		t.Fatalf("trace correlation: %+v", got)
	}
	all, _ := m.QueryLogs(ctx, "t1", LogQuery{})
	if len(all) != 2 || !all[0].TS.After(all[1].TS) {
		t.Fatalf("newest-first ordering: %+v", all)
	}

	// Erasure removes a tenant's signals and nothing else, count-verified.
	if deleted, remaining, err := m.EraseTenant(ctx, "t1"); err != nil || remaining != 0 || deleted < 1 {
		t.Fatalf("erase t1: deleted=%d remaining=%d err=%v", deleted, remaining, err)
	}
	if s, l := m.Len("t1"); s != 0 || l != 0 {
		t.Fatal("erase must remove every t1 signal")
	}
	if s, _ := m.Len("t2"); s != 1 {
		t.Fatal("erase must not touch other tenants")
	}
}

func TestMemoryBoundedPerTenant(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	batch := make([]LogRecord, memoryMaxPerTenant+100)
	for i := range batch {
		batch[i] = LogRecord{TenantID: "t1", TS: time.Now(), Body: "x"}
	}
	if err := m.WriteLogs(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, l := m.Len("t1"); l > memoryMaxPerTenant {
		t.Fatalf("memory store must stay bounded: %d", l)
	}
}
