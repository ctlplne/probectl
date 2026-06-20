// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/rum"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// fakeRUMBus captures published beacons (tenant key + payload).
type fakeRUMBus struct {
	mu       sync.Mutex
	tenants  []string
	payloads [][]byte
	fail     bool
}

func (f *fakeRUMBus) publish(_ context.Context, tenant string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return fmt.Errorf("bus down")
	}
	f.tenants = append(f.tenants, tenant)
	f.payloads = append(f.payloads, payload)
	return nil
}

func rumBeaconBody(key string) string {
	return fmt.Sprintf(`{"v":1,"key":%q,"consent":true,"host":"web.acme.example",
		"page":"/checkout/12345","vitals":{"lcp_ms":1800},"errors":0,"failed_requests":0}`, key)
}

func rumTestServer(t *testing.T, fb *fakeRUMBus) (*Server, *rum.Engine) {
	t.Helper()
	eng, apps, on, err := BuildRUM(&config.Config{
		RUMEnabled:    true,
		RUMApps:       map[string]string{"pk_abc": tenancy.DefaultTenantID.String() + "/storefront", "pk_other": "other-tenant/intranet"},
		RUMRatePerMin: 1000,
	}, intelTestLog())
	if err != nil || !on {
		t.Fatalf("BuildRUM: on=%v err=%v", on, err)
	}
	srv := testServer(fakePinger{}).WithRUM(eng, apps, fb.publish, 1000)
	return srv, eng
}

func postBeacon(srv *Server, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ingest/rum", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestBuildRUMGatingAndFailClosed(t *testing.T) {
	if _, _, on, err := BuildRUM(&config.Config{RUMEnabled: false}, intelTestLog()); on || err != nil {
		t.Fatalf("disabled: on=%v err=%v", on, err)
	}
	// Enabled without keys: startup error (an open ingest with no registry).
	if _, _, _, err := BuildRUM(&config.Config{RUMEnabled: true}, intelTestLog()); err == nil {
		t.Fatal("enabled-but-empty registry must fail startup")
	}
	// Malformed binding: startup error.
	if _, _, _, err := BuildRUM(&config.Config{
		RUMEnabled: true, RUMApps: map[string]string{"pk": "no-slash-tenant-only-is-fine"},
	}, intelTestLog()); err != nil {
		t.Fatalf("tenant-only binding is valid (app optional): %v", err)
	}
	if _, _, _, err := BuildRUM(&config.Config{
		RUMEnabled: true, RUMApps: map[string]string{"pk": "/app-without-tenant"},
	}, intelTestLog()); err == nil {
		t.Fatal("binding without a tenant must fail startup")
	}
}

func TestRUMBeaconIngestPublishesUnderVerifiedTenant(t *testing.T) {
	fb := &fakeRUMBus{}
	srv, _ := rumTestServer(t, fb)

	rec := postBeacon(srv, rumBeaconBody("pk_abc"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("beacon response must carry CORS headers")
	}
	if len(fb.payloads) != 1 || fb.tenants[0] != tenancy.DefaultTenantID.String() {
		t.Fatalf("publish wrong: tenants=%v", fb.tenants)
	}
	var r resultv1.Result
	if err := proto.Unmarshal(fb.payloads[0], &r); err != nil {
		t.Fatal(err)
	}
	// Tenant comes from the VERIFIED key; the page is redacted; the key and
	// the client address are nowhere in the stored record.
	if r.GetTenantId() != tenancy.DefaultTenantID.String() || r.GetCanaryType() != "rum" {
		t.Fatalf("result identity wrong: %+v", &r)
	}
	if r.GetAttributes()["rum.app"] != "storefront" {
		t.Errorf("app must come from the key binding, got %q", r.GetAttributes()["rum.app"])
	}
	if r.GetAttributes()["url.path"] != "/checkout/:id" {
		t.Errorf("page must be redacted, got %q", r.GetAttributes()["url.path"])
	}
	raw := string(fb.payloads[0])
	if strings.Contains(raw, "pk_abc") || strings.Contains(raw, "192.0.2.") {
		t.Error("key or client address leaked into the published record")
	}
}

func TestRUMBeaconIngestRejections(t *testing.T) {
	fb := &fakeRUMBus{}
	srv, eng := rumTestServer(t, fb)

	tests := []struct {
		name string
		body string
		code int
	}{
		{"unknown key", rumBeaconBody("pk_forged"), http.StatusUnauthorized},
		{"no key", `{"v":1,"consent":true,"host":"a.example","page":"/"}`, http.StatusUnauthorized},
		{"no consent", `{"v":1,"key":"pk_abc","consent":false,"host":"a.example","page":"/"}`, http.StatusBadRequest},
		{"pii field", `{"v":1,"key":"pk_abc","consent":true,"host":"a.example","page":"/","user_email":"x@y.z"}`, http.StatusBadRequest},
		{"oversized", `{"v":1,"key":"pk_abc","consent":true,"host":"a.example","page":"/` + strings.Repeat("x", rum.MaxBeaconBytes) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		if rec := postBeacon(srv, tc.body); rec.Code != tc.code {
			t.Errorf("%s: status = %d want %d (%s)", tc.name, rec.Code, tc.code, rec.Body.String())
		}
	}
	if len(fb.payloads) != 0 {
		t.Fatalf("no rejected beacon may reach the bus, got %d", len(fb.payloads))
	}
	// Rejections are attributed to the key's tenant (privacy honesty counters).
	p := eng.Snapshot(tenancy.DefaultTenantID.String()).Privacy
	if p.RejectedNoConsent != 1 || p.RejectedMalformed != 1 {
		t.Fatalf("rejection counters wrong: %+v", p)
	}
}

func TestRUMBeaconRateLimitAndPreflight(t *testing.T) {
	fb := &fakeRUMBus{}
	eng, apps, _, err := BuildRUM(&config.Config{
		RUMEnabled: true, RUMApps: map[string]string{"pk_abc": "t1/shop"}, RUMRatePerMin: 1,
	}, intelTestLog())
	if err != nil {
		t.Fatal(err)
	}
	srv := testServer(fakePinger{}).WithRUM(eng, apps, fb.publish, 1)

	if rec := postBeacon(srv, rumBeaconBody("pk_abc")); rec.Code != http.StatusAccepted {
		t.Fatalf("first beacon: %d", rec.Code)
	}
	rec := postBeacon(srv, rumBeaconBody("pk_abc"))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("second beacon must rate-limit with Retry-After, got %d", rec.Code)
	}

	// CORS preflight (browsers send OPTIONS before JSON posts).
	req := httptest.NewRequest(http.MethodOptions, "/ingest/rum", nil)
	prec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(prec, req)
	if prec.Code != http.StatusNoContent || prec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatalf("preflight wrong: %d", prec.Code)
	}
}

// SEC-005: when an app key has an operator-configured allowed-origins list, the
// beacon reflects the request Origin only if it is on the list; an off-list
// Origin is NOT reflected (no Access-Control-Allow-Origin), so the browser
// blocks the cross-origin response. No allow-list ⇒ wildcard as before.
func TestRUMBeaconCORSAllowList(t *testing.T) {
	fb := &fakeRUMBus{}
	eng, apps, _, err := BuildRUM(&config.Config{
		RUMEnabled: true, RUMApps: map[string]string{"pk_abc": "t1/shop"}, RUMRatePerMin: 100,
	}, intelTestLog())
	if err != nil {
		t.Fatal(err)
	}
	// Attach an operator allow-list to the app key.
	app := apps["pk_abc"]
	app.AllowedOrigins = []string{"https://shop.example"}
	apps["pk_abc"] = app
	srv := testServer(fakePinger{}).WithRUM(eng, apps, fb.publish, 100)

	post := func(origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/ingest/rum", strings.NewReader(rumBeaconBody("pk_abc")))
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	// On-list Origin is echoed exactly (not "*").
	on := post("https://shop.example")
	if got := on.Header().Get("Access-Control-Allow-Origin"); got != "https://shop.example" {
		t.Errorf("on-list Allow-Origin = %q, want the exact origin", got)
	}
	// Off-list Origin is NOT reflected.
	off := post("https://evil.example")
	if got := off.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("off-list Allow-Origin = %q, want empty (not reflected)", got)
	}
	// Credentials are never allowed on either path.
	if on.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("RUM beacon must never set Access-Control-Allow-Credentials")
	}
}

func TestRUMEndpointNotWiredAndUnavailableIngest(t *testing.T) {
	srv := testServer(fakePinger{})
	rec := do(srv, http.MethodGet, "/v1/rum")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Running bool `json:"rum_running"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Running {
		t.Fatal("unwired endpoint must report rum_running=false")
	}
	if rec := postBeacon(srv, rumBeaconBody("pk_abc")); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired ingest must answer 503, got %d", rec.Code)
	}
}

// Beacon → bus → consumer → engine → /v1/rum, with the synthetic plane joined:
// the S47b 'Done when' (RUM and synthetic correlate for the same service),
// tenant-scoped end to end.
func TestRUMEndToEndConvergenceAndIsolation(t *testing.T) {
	fb := &fakeRUMBus{}
	srv, eng := rumTestServer(t, fb)
	incStore := incident.NewMemoryStore()
	correlator := incident.NewCorrelator(incStore, time.Hour, intelTestLog())
	rc := NewRUMConsumer(nil, eng, correlator, intelTestLog())
	tid := tenancy.DefaultTenantID.String()
	now := time.Now()

	// Synthetics against the host are failing.
	for i := 0; i < 4; i++ {
		raw, _ := proto.Marshal(&resultv1.Result{
			TenantId: tid, CanaryType: "http", ServerAddress: "web.acme.example:443",
			Success: false, StartTimeUnixNano: now.Add(time.Duration(i) * time.Minute).UnixNano(),
		})
		if err := rc.handleSynthetic(context.Background(), bus.Message{Value: raw}); err != nil {
			t.Fatal(err)
		}
	}
	// Real users error too: beacons in via the handler, then drained into the
	// consumer as the bus would deliver them.
	for i := 0; i < 25; i++ {
		errs := 0
		if i%4 == 0 {
			errs = 1
		}
		body := fmt.Sprintf(`{"v":1,"key":"pk_abc","consent":true,"host":"web.acme.example",
			"page":"/checkout/%d","vitals":{"lcp_ms":1500},"errors":%d,"failed_requests":0}`, 1000+i, errs)
		if rec := postBeacon(srv, body); rec.Code != http.StatusAccepted {
			t.Fatalf("beacon %d: %d", i, rec.Code)
		}
	}
	for _, payload := range fb.payloads {
		if err := rc.handleRUMEvent(context.Background(), bus.Message{Value: payload}); err != nil {
			t.Fatal(err)
		}
	}

	// The convergence verdict, served tenant-scoped.
	rec := do(srv, http.MethodGet, "/v1/rum")
	var resp struct {
		Running bool            `json:"rum_running"`
		Apps    []rum.AppStatus `json:"apps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || len(resp.Apps) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Apps[0].Verdict != rum.VerdictUserImpactConfirmed {
		t.Fatalf("verdict = %s want %s", resp.Apps[0].Verdict, rum.VerdictUserImpactConfirmed)
	}
	if resp.Apps[0].Pages[0].Page != "/checkout/:id" {
		t.Fatalf("page grouping must be redacted: %+v", resp.Apps[0].Pages)
	}

	// The correlation landed as a tenant-scoped incident — and only there.
	incs, err := incStore.OpenIncidents(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) == 0 {
		t.Fatal("the convergence signal must open a tenant-scoped incident")
	}
	if other, _ := incStore.OpenIncidents(context.Background(), "other-tenant"); len(other) != 0 {
		t.Fatal("no other tenant may receive the incident")
	}
	if snapOther := eng.Snapshot("other-tenant"); len(snapOther.Apps) != 0 {
		t.Fatal("cross-tenant app leak in the engine")
	}
}

func TestRUMPublicKeyReplayDoesNotOpenIncidentWithoutSyntheticCorroboration(t *testing.T) {
	fb := &fakeRUMBus{}
	srv, eng := rumTestServer(t, fb)
	incStore := incident.NewMemoryStore()
	correlator := incident.NewCorrelator(incStore, time.Hour, intelTestLog())
	rc := NewRUMConsumer(nil, eng, correlator, intelTestLog())
	tid := tenancy.DefaultTenantID.String()

	// A public RUM key can be replayed by an attacker. Even enough forged views
	// to make the RUM-only verdict degraded must not create a paging-grade
	// incident without independent synthetic-plane corroboration.
	for i := 0; i < 20; i++ {
		body := fmt.Sprintf(`{"v":1,"key":"pk_abc","consent":true,"host":"web.acme.example",
			"page":"/checkout/%d","vitals":{"lcp_ms":4500},"errors":1,"failed_requests":1}`, 2000+i)
		if rec := postBeacon(srv, body); rec.Code != http.StatusAccepted {
			t.Fatalf("replayed beacon %d: %d", i, rec.Code)
		}
	}
	for _, payload := range fb.payloads {
		if err := rc.handleRUMEvent(context.Background(), bus.Message{Value: payload}); err != nil {
			t.Fatal(err)
		}
	}

	snap := eng.Snapshot(tid)
	if len(snap.Apps) != 1 {
		t.Fatalf("expected RUM-only evidence to remain visible, got %+v", snap.Apps)
	}
	if snap.Apps[0].Verdict != rum.VerdictUserOnly || !snap.Apps[0].RUMDegraded {
		t.Fatalf("RUM-only verdict = %+v, want degraded blind spot", snap.Apps[0])
	}
	incs, err := incStore.OpenIncidents(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) != 0 {
		t.Fatalf("public-key RUM replay must not open incidents without corroboration: %+v", incs)
	}
}

func TestRUMConsumerDropsGarbageAndUnscoped(t *testing.T) {
	eng := rum.NewEngine()
	rc := NewRUMConsumer(nil, eng, nil, intelTestLog())
	if err := rc.handleRUMEvent(context.Background(), bus.Message{Value: []byte("junk")}); err != nil {
		t.Fatal("garbage must be skipped, not fatal")
	}
	raw, _ := proto.Marshal(&resultv1.Result{CanaryType: "rum", ServerAddress: "h.example", Success: true})
	if err := rc.handleRUMEvent(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}
	// Non-web synthetic types are ignored by the synthetic join.
	raw, _ = proto.Marshal(&resultv1.Result{TenantId: "t1", CanaryType: "icmp", ServerAddress: "h.example", Success: false})
	if err := rc.handleSynthetic(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}
	if apps := eng.Snapshot("t1").Apps; len(apps) != 0 {
		t.Fatalf("nothing should have ingested, got %+v", apps)
	}
}
