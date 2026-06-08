package tenantlife

import (
	"context"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
)

// TENANT-008: tenant erasure must cover the externally-ingested OTLP
// trace/log store — a whole tenant-PII telemetry plane the audit's
// "erasure across 5+ stores" claim had overstated. The attestation must
// enumerate the "otel" store, count-verified to zero, while a neighbor
// tenant's traces/logs stay untouched.
func TestErasureCoversOtelStore(t *testing.T) {
	ctx := context.Background()
	mem := otelstore.NewMemory()
	if err := mem.WriteSpans(ctx, []otelstore.Span{
		{TenantID: "victim", TraceID: "aa", SpanID: "s1", Service: "svc", Start: time.Now()},
		{TenantID: "victim", TraceID: "bb", SpanID: "s2", Service: "svc", Start: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteLogs(ctx, []otelstore.LogRecord{
		{TenantID: "victim", TS: time.Now(), Body: "TENANT-SECRET log line"},
	}); err != nil {
		t.Fatal(err)
	}
	// A neighbor tenant whose OTLP data MUST survive the erase.
	if err := mem.WriteSpans(ctx, []otelstore.Span{
		{TenantID: "other", TraceID: "cc", SpanID: "s3", Service: "svc", Start: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}

	e := New(nil, nil, nil, nil, nil, "note-only", nil).
		WithOtel(mem).
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })

	att, err := e.Erase(ctx, "victim", "victim-slug", "compliance-officer")
	if err != nil {
		t.Fatalf("erase: %v", err)
	}

	// The attestation enumerates the otel store, count-verified to zero.
	otel := storeResult(att, "otel")
	if otel == nil {
		t.Fatal("attestation must enumerate the otel store (TENANT-008)")
	}
	if !otel.VerifiedZero || otel.Deleted < 3 {
		t.Fatalf("otel store not erased/verified-zero: %+v", *otel)
	}
	if !att.Complete {
		t.Fatalf("attestation must be complete: %+v", att.Stores)
	}

	// Victim's OTLP data is gone; the neighbor is untouched.
	if s, l := mem.Len("victim"); s != 0 || l != 0 {
		t.Fatalf("victim OTLP not erased: spans=%d logs=%d", s, l)
	}
	if s, _ := mem.Len("other"); s != 1 {
		t.Fatal("neighbor tenant OTLP must be untouched")
	}
}

// Without an otel store wired, the attestation honestly records it as
// "store not deployed" (never silently skipped) and stays complete.
func TestErasureOtelStoreNotDeployed(t *testing.T) {
	e := New(nil, nil, nil, nil, nil, "note-only", nil).
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	att, err := e.Erase(context.Background(), "t", "slug", "actor")
	if err != nil {
		t.Fatal(err)
	}
	otel := storeResult(att, "otel")
	if otel == nil || !otel.VerifiedZero || otel.Notes != "store not deployed" {
		t.Fatalf("absent otel store must be recorded not-deployed: %+v", otel)
	}
}

func storeResult(att Attestation, name string) *StoreResult {
	for i := range att.Stores {
		if att.Stores[i].Store == name {
			return &att.Stores[i]
		}
	}
	return nil
}
