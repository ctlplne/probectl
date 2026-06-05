// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/usage"
)

var t0 = time.Date(2026, 6, 5, 14, 23, 45, 0, time.UTC) // mid-hour

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestMeteringAccuracy is the sprint's named accuracy test: known activity →
// exact counts, bucketed at record time, across hour boundaries, concurrent
// writers, and a failed flush (lossless: delayed, never lost or doubled).
func TestMeteringAccuracy(t *testing.T) {
	store := NewMemStore()
	now := t0
	rec := NewRecorder(store, testLog()).WithClock(func() time.Time { return now })
	ctx := context.Background()

	// Known activity: 100 results + bytes from 10 concurrent writers.
	var wg sync.WaitGroup
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				rec.Record("tnA", usage.MeterResultsIngested, 1)
				rec.Record("tnA", usage.MeterIngestBytes, 512)
			}
		}()
	}
	wg.Wait()
	rec.Record("tnB", usage.MeterAICalls, 3)

	// A failed flush loses nothing.
	store.FailNextAdd()
	if err := rec.Flush(ctx); err == nil {
		t.Fatal("forced flush failure must surface")
	}
	// Activity continues after the failure, same buckets.
	rec.Record("tnA", usage.MeterResultsIngested, 5)
	if err := rec.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	// Cross the hour boundary: new records land in the NEXT bucket.
	now = t0.Add(45 * time.Minute) // 15:08 — next hour bucket
	rec.Record("tnA", usage.MeterResultsIngested, 7)
	if err := rec.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	recs, err := store.Query(ctx, t0.Add(-time.Hour), t0.Add(2*time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]int64{}
	for _, r := range recs {
		byKey[r.TenantID+"|"+r.Meter+"|"+r.PeriodStart.UTC().Format("15:04")] = r.Value
	}
	if byKey["tnA|results_ingested|14:00"] != 105 { // 100 concurrent + 5 post-failure
		t.Fatalf("hour-1 results: %+v", byKey)
	}
	if byKey["tnA|ingest_bytes|14:00"] != 51200 {
		t.Fatalf("bytes: %+v", byKey)
	}
	if byKey["tnA|results_ingested|15:00"] != 7 {
		t.Fatalf("hour-2 results: %+v", byKey)
	}
	if byKey["tnB|ai_calls|14:00"] != 3 {
		t.Fatalf("ai calls: %+v", byKey)
	}
	// Exactly the expected rows — nothing doubled by the failed flush.
	if len(recs) != 4 {
		t.Fatalf("row count: %d (%+v)", len(recs), recs)
	}
}

// TestCollectorSnapshots: gauges come from per-tenant counts (the source of
// truth by construction); one tenant's failure skips only that tenant.
func TestCollectorSnapshots(t *testing.T) {
	store := NewMemStore()
	counts := map[string][2]int64{"tnA": {3, 12}, "tnB": {1, 4}}
	col := NewCollector(store,
		func(context.Context) ([]string, error) { return []string{"tnA", "tnB", "tnBroken"}, nil },
		func(_ context.Context, id string) (int64, int64, error) {
			if id == "tnBroken" {
				return 0, 0, context.DeadlineExceeded
			}
			c := counts[id]
			return c[0], c[1], nil
		}, testLog()).WithClock(func() time.Time { return t0 })

	if err := col.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	recs, _ := store.Query(context.Background(), t0.Add(-time.Hour), t0.Add(time.Hour), "")
	got := map[string]int64{}
	for _, r := range recs {
		if r.Kind != KindGauge {
			t.Fatalf("snapshot rows must be gauges: %+v", r)
		}
		got[r.TenantID+"|"+r.Meter] = r.Value
	}
	want := map[string]int64{"tnA|agents": 3, "tnA|tests": 12, "tnB|agents": 1, "tnB|tests": 4}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("gauge %s = %d, want %d (%+v)", k, got[k], v, got)
		}
	}
	if len(recs) != 4 {
		t.Fatalf("the broken tenant must be skipped, not zeroed: %+v", recs)
	}
}

// TestUsageExportFormats is the named export-format test: the CSV and JSONL
// contracts, byte-for-byte.
func TestUsageExportFormats(t *testing.T) {
	records := []UsageRecord{
		{TenantID: "11111111-1111-1111-1111-111111111111", TenantSlug: "acme",
			Meter: "results_ingested", Kind: "counter",
			PeriodStart: t0.Truncate(time.Hour), PeriodEnd: t0.Truncate(time.Hour).Add(time.Hour),
			Value: 105, Unit: "count"},
		{TenantID: "22222222-2222-2222-2222-222222222222", TenantSlug: "globex",
			Meter: "ingest_bytes", Kind: "counter",
			PeriodStart: t0.Truncate(time.Hour), PeriodEnd: t0.Truncate(time.Hour).Add(time.Hour),
			Value: 51200, Unit: "bytes"},
		{TenantID: "22222222-2222-2222-2222-222222222222", TenantSlug: "globex",
			Meter: "agents", Kind: "gauge",
			PeriodStart: t0.Truncate(time.Hour), PeriodEnd: t0.Truncate(time.Hour).Add(time.Hour),
			Value: 3, Unit: "count"},
	}

	var csvBuf bytes.Buffer
	if err := WriteCSV(&csvBuf, records); err != nil {
		t.Fatal(err)
	}
	wantCSV := strings.Join([]string{
		"tenant_id,tenant_slug,meter,kind,period_start,period_end,value,unit",
		"11111111-1111-1111-1111-111111111111,acme,results_ingested,counter,2026-06-05T14:00:00Z,2026-06-05T15:00:00Z,105,count",
		"22222222-2222-2222-2222-222222222222,globex,ingest_bytes,counter,2026-06-05T14:00:00Z,2026-06-05T15:00:00Z,51200,bytes",
		"22222222-2222-2222-2222-222222222222,globex,agents,gauge,2026-06-05T14:00:00Z,2026-06-05T15:00:00Z,3,count",
		"",
	}, "\n")
	if csvBuf.String() != wantCSV {
		t.Fatalf("CSV contract drifted:\n got: %q\nwant: %q", csvBuf.String(), wantCSV)
	}

	var jl bytes.Buffer
	if err := WriteJSONL(&jl, records); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(jl.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("jsonl lines: %d", len(lines))
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tenant_id", "tenant_slug", "meter", "kind", "period_start", "period_end", "value", "unit"} {
		if _, ok := first[k]; !ok {
			t.Fatalf("jsonl missing field %q: %s", k, lines[0])
		}
	}
	if first["value"].(float64) != 105 || first["unit"] != "count" {
		t.Fatalf("jsonl values: %+v", first)
	}
}

// TestRollupDay: counters sum exactly; gauges take the peak.
func TestRollupDay(t *testing.T) {
	day := time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	in := []UsageRecord{
		{TenantID: "a", Meter: "results_ingested", Kind: KindCounter, PeriodStart: day.Add(1 * time.Hour), Value: 10},
		{TenantID: "a", Meter: "results_ingested", Kind: KindCounter, PeriodStart: day.Add(2 * time.Hour), Value: 32},
		{TenantID: "a", Meter: "agents", Kind: KindGauge, PeriodStart: day.Add(1 * time.Hour), Value: 5},
		{TenantID: "a", Meter: "agents", Kind: KindGauge, PeriodStart: day.Add(9 * time.Hour), Value: 3},
	}
	out := Rollup(in, RollupDay)
	if len(out) != 2 {
		t.Fatalf("rollup rows: %+v", out)
	}
	for _, r := range out {
		switch r.Meter {
		case "results_ingested":
			if r.Value != 42 || !r.PeriodStart.Equal(day) || !r.PeriodEnd.Equal(day.Add(24*time.Hour)) {
				t.Fatalf("counter rollup: %+v", r)
			}
		case "agents":
			if r.Value != 5 { // peak, not last
				t.Fatalf("gauge rollup must be peak: %+v", r)
			}
		}
	}
	// Hour granularity passes through untouched.
	if got := Rollup(in, RollupHour); len(got) != 4 {
		t.Fatalf("hour rollup must be identity: %+v", got)
	}
}

// TestQuotaEnforcement is the named quota test: at-limit creates are
// rejected with a descriptive error, under-limit allowed, absent quota =
// unlimited, unknown resources allowed, and infrastructure failures degrade
// OPEN (quota is a billing control, not a security boundary).
func TestQuotaEnforcement(t *testing.T) {
	store := NewMemStore()
	five := 5
	zero := 0
	if err := store.SetQuota(context.Background(), Quota{TenantID: "tnA", MaxAgents: &five, MaxTests: &zero}); err != nil {
		t.Fatal(err)
	}
	counts := map[string][2]int64{"tnA": {4, 9}}
	var countErr error
	checker := NewQuotaChecker(store,
		func(_ context.Context, id string) (int64, int64, error) {
			if countErr != nil {
				return 0, 0, countErr
			}
			c := counts[id]
			return c[0], c[1], nil
		}, time.Minute)
	ctx := context.Background()

	// Under limit: allowed.
	if err := checker.AllowCreate(ctx, "tnA", usage.MeterAgents); err != nil {
		t.Fatalf("4 of 5 agents must allow: %v", err)
	}
	// At limit: rejected, descriptively.
	counts["tnA"] = [2]int64{5, 9}
	err := checker.AllowCreate(ctx, "tnA", usage.MeterAgents)
	if err == nil || !strings.Contains(err.Error(), "5 of 5 agents") {
		t.Fatalf("at-limit must reject with detail: %v", err)
	}
	// A zero quota blocks every create of that kind.
	if err := checker.AllowCreate(ctx, "tnA", usage.MeterTests); err == nil {
		t.Fatal("zero test quota must reject")
	}
	// No quota row = unlimited.
	if err := checker.AllowCreate(ctx, "tnB", usage.MeterAgents); err != nil {
		t.Fatalf("absent quota must allow: %v", err)
	}
	// Unknown resources are not gated.
	if err := checker.AllowCreate(ctx, "tnA", "dashboards"); err != nil {
		t.Fatalf("unknown resource must allow: %v", err)
	}
	// Count failure degrades open.
	countErr = context.DeadlineExceeded
	if err := checker.AllowCreate(ctx, "tnA", usage.MeterAgents); err != nil {
		t.Fatalf("count failure must degrade open: %v", err)
	}
}

// TestQuotaCacheInvalidation: a quota update is visible immediately after
// Invalidate (the provider API calls it on PUT).
func TestQuotaCacheInvalidation(t *testing.T) {
	store := NewMemStore()
	one := 1
	_ = store.SetQuota(context.Background(), Quota{TenantID: "tnA", MaxTests: &one})
	checker := NewQuotaChecker(store,
		func(context.Context, string) (int64, int64, error) { return 0, 1, nil }, time.Hour)
	ctx := context.Background()

	if err := checker.AllowCreate(ctx, "tnA", usage.MeterTests); err == nil {
		t.Fatal("1 of 1 must reject")
	}
	ten := 10
	_ = store.SetQuota(ctx, Quota{TenantID: "tnA", MaxTests: &ten})
	// Cached for an hour — still rejecting…
	if err := checker.AllowCreate(ctx, "tnA", usage.MeterTests); err == nil {
		t.Fatal("stale cache expected to reject")
	}
	checker.Invalidate("tnA")
	if err := checker.AllowCreate(ctx, "tnA", usage.MeterTests); err != nil {
		t.Fatalf("post-invalidate must allow: %v", err)
	}
}

// TestUsageSeamWiring: the core seam routes Record calls into the recorder
// and AllowCreate into the checker; uninstalled = no-op/allow-all.
func TestUsageSeamWiring(t *testing.T) {
	store := NewMemStore()
	rec := NewRecorder(store, testLog()).WithClock(func() time.Time { return t0 })
	usage.SetRecorder(rec)
	defer usage.SetRecorder(nil)

	usage.Record("tnA", usage.MeterResultsIngested, 2)
	usage.Record("", usage.MeterResultsIngested, 2)    // ignored: no tenant
	usage.Record("tnA", usage.MeterResultsIngested, 0) // ignored: zero delta
	if err := rec.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	recs, _ := store.Query(context.Background(), t0.Add(-time.Hour), t0.Add(time.Hour), "tnA")
	if len(recs) != 1 || recs[0].Value != 2 {
		t.Fatalf("seam recording: %+v", recs)
	}

	one := 1
	_ = store.SetQuota(context.Background(), Quota{TenantID: "tnA", MaxTests: &one})
	checker := NewQuotaChecker(store, func(context.Context, string) (int64, int64, error) { return 0, 1, nil }, time.Minute)
	usage.SetQuotaChecker(checker)
	defer usage.SetQuotaChecker(nil)
	if err := usage.AllowCreate(context.Background(), "tnA", usage.MeterTests); err == nil {
		t.Fatal("seam quota gate must reject at limit")
	}
	usage.SetQuotaChecker(nil)
	if err := usage.AllowCreate(context.Background(), "tnA", usage.MeterTests); err != nil {
		t.Fatalf("uninstalled checker must allow: %v", err)
	}
}
