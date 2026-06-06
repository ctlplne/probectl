// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/ee/billing"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/usage"
)

// The S-T3 surface on the provider plane: usage/showback, the billing-export
// feed, and quota management — hidden entirely when metering is unattached.

func seedUsage(t *testing.T, store *billing.MemStore, now time.Time) {
	t.Helper()
	ctx := context.Background()
	store.SetSlug("tnA", "acme")
	store.SetSlug("tnB", "globex")
	h := billing.PeriodStart(now)
	if err := store.AddCounters(ctx, []billing.CounterDelta{
		{TenantID: "tnA", Meter: usage.MeterResultsIngested, Period: h.Add(-2 * billing.Period), Delta: 40},
		{TenantID: "tnA", Meter: usage.MeterResultsIngested, Period: h, Delta: 2},
		{TenantID: "tnB", Meter: usage.MeterAICalls, Period: h, Delta: 7},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetGauge(ctx, "tnA", usage.MeterAgents, h, 3); err != nil {
		t.Fatal(err)
	}
}

func meteredFixture(t *testing.T) (*fixture, *billing.MemStore, string) {
	t.Helper()
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	// Pin a fixed mid-month, mid-day clock so the metering buckets (h and
	// h-2*Period) always land on the same calendar day — otherwise the day
	// rollup splits them whenever the test runs within 2h of UTC midnight.
	*f.now = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	store := billing.NewMemStore()
	f.h.WithMetering(&Metering{Store: store})
	token := f.bootstrapAndLogin(t)
	seedUsage(t, store, *f.now)
	return f, store, token
}

func TestUsageShowback(t *testing.T) {
	f, _, token := meteredFixture(t)

	// Day rollup (default): tnA's two hourly buckets sum.
	rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/usage", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("usage: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Items  []billing.UsageRecord `json:"items"`
		Meters []string              `json:"meters"`
	}
	mustDecode(t, rec, &out)
	if len(out.Meters) != 6 {
		t.Fatalf("meter vocabulary: %v", out.Meters)
	}
	byKey := map[string]int64{}
	for _, r := range out.Items {
		byKey[r.TenantSlug+"|"+r.Meter+"|"+r.Kind] = r.Value
	}
	if byKey["acme|results_ingested|counter"] != 42 || byKey["globex|ai_calls|counter"] != 7 || byKey["acme|agents|gauge"] != 3 {
		t.Fatalf("showback truth: %+v", byKey)
	}

	// Tenant filter + hourly granularity.
	rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/usage?tenant_id=tnA&rollup=hour", nil)
	mustDecode(t, rec, &out)
	for _, r := range out.Items {
		if r.TenantID != "tnA" {
			t.Fatalf("tenant filter leaked: %+v", r)
		}
	}
	if len(out.Items) != 3 { // two hourly counter buckets + one gauge
		t.Fatalf("hourly rows: %+v", out.Items)
	}

	// Bad rollup is refused.
	if rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/usage?rollup=fortnight", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad rollup: %d", rec.Code)
	}
}

func TestUsageExportFeed(t *testing.T) {
	f, _, token := meteredFixture(t)

	rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/usage/export?rollup=day", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("csv content type: %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "probectl-usage.csv") {
		t.Fatalf("content disposition: %q", cd)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "tenant_id,tenant_slug,meter,kind,period_start,period_end,value,unit") {
		t.Fatalf("csv header contract: %q", body)
	}
	if !strings.Contains(body, ",acme,results_ingested,counter,") || !strings.Contains(body, ",42,count") {
		t.Fatalf("csv rows: %s", body)
	}

	rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/usage/export?format=jsonl", nil)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/x-ndjson") {
		t.Fatalf("jsonl export: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), `"tenant_slug":"acme"`) {
		t.Fatalf("jsonl body: %s", rec.Body.String())
	}
	if rec = f.doAuthed(t, token, http.MethodGet, "/provider/v1/usage/export?format=xml", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad format: %d", rec.Code)
	}
}

func TestQuotaManagement(t *testing.T) {
	f, store, admin := meteredFixture(t)

	// Default: unlimited.
	rec := f.doAuthed(t, admin, http.MethodGet, "/provider/v1/tenants/tnA/quotas", nil)
	var q billing.Quota
	mustDecode(t, rec, &q)
	if rec.Code != http.StatusOK || q.MaxAgents != nil || q.MaxTests != nil {
		t.Fatalf("default quota: %d %+v", rec.Code, q)
	}

	// Admin sets quotas; audited; readable back.
	rec = f.doAuthed(t, admin, http.MethodPut, "/provider/v1/tenants/tnA/quotas",
		map[string]any{"max_agents": 5, "max_tests": 100})
	if rec.Code != http.StatusOK {
		t.Fatalf("put quotas: %d %s", rec.Code, rec.Body.String())
	}
	got, _ := store.QuotaFor(context.Background(), "tnA")
	if got.MaxAgents == nil || *got.MaxAgents != 5 || got.UpdatedBy != "root@msp.example" {
		t.Fatalf("stored quota: %+v", got)
	}
	if f.audit.count("provider.quota_set") != 1 {
		t.Fatal("quota changes must be audited")
	}
	// Negative quotas refused.
	if rec = f.doAuthed(t, admin, http.MethodPut, "/provider/v1/tenants/tnA/quotas",
		map[string]any{"max_agents": -1}); rec.Code != http.StatusBadRequest {
		t.Fatalf("negative quota: %d", rec.Code)
	}

	// SoD: a plain operator cannot set quotas (billing-affecting).
	rec2 := f.doAuthed(t, admin, http.MethodPost, "/provider/v1/operators",
		map[string]string{"email": "op@msp.example", "name": "Op", "role": "operator"})
	var created struct {
		EnrollToken string `json:"enroll_token"`
	}
	mustDecode(t, rec2, &created)
	op := f.enrollAndLogin(t, created.EnrollToken, "op@msp.example", "operator-pw-123456")
	if rec = f.doAuthed(t, op, http.MethodPut, "/provider/v1/tenants/tnA/quotas",
		map[string]any{"max_tests": 1}); rec.Code != http.StatusForbidden {
		t.Fatalf("SoD: operator set a quota: %d", rec.Code)
	}
	// …but can read usage (showback is operator work).
	if rec = f.doAuthed(t, op, http.MethodGet, "/provider/v1/usage", nil); rec.Code != http.StatusOK {
		t.Fatalf("operator usage read: %d", rec.Code)
	}
}

// TestMeteringHiddenWhenUnattached: without the metering capability the S-T3
// routes answer not_found — indistinguishable from unknown paths.
func TestMeteringHiddenWhenUnattached(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	token := f.bootstrapAndLogin(t) // no WithMetering
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/provider/v1/usage"},
		{http.MethodGet, "/provider/v1/usage/export"},
		{http.MethodGet, "/provider/v1/tenants/tnA/quotas"},
		{http.MethodPut, "/provider/v1/tenants/tnA/quotas"},
	} {
		body := map[string]any{}
		var rec = f.doAuthed(t, token, probe.method, probe.path, body)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s must hide when unattached: %d", probe.method, probe.path, rec.Code)
		}
	}
}

// TestQuotaWriteReadOnlyDegrade: the license read-only ladder blocks quota
// writes (config mutations) while usage reads keep working.
func TestQuotaWriteReadOnlyDegrade(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, -31*24*time.Hour)) // read_only
	*f.now = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	store := billing.NewMemStore()
	f.h.WithMetering(&Metering{Store: store})
	token := f.bootstrapAndLoginReadOnly(t)
	seedUsage(t, store, *f.now)

	if rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/usage", nil); rec.Code != http.StatusOK {
		t.Fatalf("usage read in read-only: %d", rec.Code)
	}
	rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/tnA/quotas", map[string]any{"max_tests": 5})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "license_read_only") {
		t.Fatalf("quota write in read-only: %d %s", rec.Code, rec.Body.String())
	}
}
