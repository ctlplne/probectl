// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package terraformprovider

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestProviderPrivateCA(t *testing.T) {
	p := New()
	if p.Schema["ca_file"] == nil {
		t.Fatal("provider must expose a private CA bundle")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthHeaders(t, r, "tenant-a", "token-a")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	dir := t.TempDir()
	valid := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(valid, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(dir, "invalid.pem")
	if err := os.WriteFile(invalid, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, file                string
		configError, requestError bool
	}{
		{"trusted", valid, false, false},
		{"system-roots", "", false, true},
		{"malformed", invalid, true, false},
		{"missing", filepath.Join(dir, "missing.pem"), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, p.Schema, map[string]any{"api_url": srv.URL, "tenant": "tenant-a", "token": "token-a", "ca_file": tc.file})
			meta, diags := configure(context.Background(), d)
			if diags.HasError() != tc.configError {
				t.Fatalf("configuration error = %v, want %v", diags, tc.configError)
			}
			if tc.configError {
				return
			}
			_, err := meta.(*client).do(context.Background(), http.MethodGet, "/v1/tests", nil, nil)
			if (err != nil) != tc.requestError {
				t.Fatalf("request error = %v, want error %v", err, tc.requestError)
			}
		})
	}
	t.Setenv("PROBECTL_CA_FILE", valid)
	d := schema.TestResourceDataRaw(t, p.Schema, map[string]any{"api_url": srv.URL})
	if d.Get("ca_file") != valid {
		t.Fatal("CA environment default not applied")
	}
}

func TestProviderInternalValidateAndConfigure(t *testing.T) {
	p := New()
	if err := p.InternalValidate(); err != nil {
		t.Fatalf("provider schema should validate: %v", err)
	}
	for _, name := range []string{
		"probectl_tenant", "probectl_tenants", "probectl_test",
		"probectl_tests", "probectl_agent", "probectl_agents",
	} {
		if p.DataSourcesMap[name] == nil {
			t.Fatalf("provider does not register data source %q", name)
		}
	}

	for _, raw := range []string{"https://probectl.example.com", "http://127.0.0.1:18080", "http://localhost:18080"} {
		if err := validateAPIURL(raw); err != nil {
			t.Fatalf("validateAPIURL(%q) unexpected error: %v", raw, err)
		}
	}
	for _, raw := range []string{"", "http://probectl.example.com"} {
		if err := validateAPIURL(raw); err == nil {
			t.Fatalf("validateAPIURL(%q) should fail closed", raw)
		}
	}

	d := schema.TestResourceDataRaw(t, p.Schema, map[string]any{
		"api_url": "http://127.0.0.1:18080/",
		"tenant":  "tenant-a",
		"token":   "token-a",
	})
	meta, diags := configure(context.Background(), d)
	if diags.HasError() {
		t.Fatalf("configure diagnostics: %v", diags)
	}
	c := meta.(*client)
	if c.baseURL != "http://127.0.0.1:18080" || c.tenant != "tenant-a" || c.token != "token-a" {
		t.Fatalf("configure returned wrong client: %#v", c)
	}
}

func TestTestResourceCRUDTenantHeaders(t *testing.T) {
	var sawCreate bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthHeaders(t, r, "tenant-a", "token-a")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tests":
			sawCreate = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			if body["name"] != "edge dns" || body["type"] != "dns" || body["target"] != "1.1.1.1" {
				t.Fatalf("wrong create body: %#v", body)
			}
			if params, ok := body["params"].(map[string]any); !ok || params["qtype"] != "A" {
				t.Fatalf("params not preserved: %#v", body["params"])
			}
			_, _ = w.Write([]byte(`{"id":"test-1"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tests/test-1":
			_, _ = w.Write([]byte(`{"id":"test-1","name":"edge dns","type":"dns","target":"1.1.1.1","interval_seconds":30,"timeout_seconds":3,"enabled":true}`))
		case r.Method == http.MethodPut && r.URL.Path == "/v1/tests/test-1":
			_, _ = w.Write([]byte(`{"id":"test-1"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/tests/test-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceTest().Schema, map[string]any{
		"name":             "edge dns",
		"type":             "dns",
		"target":           "1.1.1.1",
		"interval_seconds": 30,
		"timeout_seconds":  3,
		"enabled":          true,
		"params":           map[string]any{"qtype": "A"},
	})
	meta := testClient(srv.URL, "tenant-a", "token-a")
	assertNoDiagnostics(t, createTest(context.Background(), d, meta))
	if d.Id() != "test-1" || !sawCreate {
		t.Fatalf("create did not set expected id")
	}
	assertNoDiagnostics(t, readTest(context.Background(), d, meta))
	assertNoDiagnostics(t, updateTest(context.Background(), d, meta))
	assertNoDiagnostics(t, deleteByPath("/v1/tests/{id}")(context.Background(), d, meta))
	if d.Id() != "" {
		t.Fatalf("delete should clear id, got %q", d.Id())
	}
}

func TestProviderTenantLifecycleUsesProviderPlane(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Probectl-Tenant"); got != "" {
			t.Fatalf("provider plane request should not inherit a tenant header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/provider/v1/tenants":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode tenant body: %v", err)
			}
			if body["slug"] != "acme" || body["name"] != "Acme Networks" {
				t.Fatalf("wrong tenant create body: %#v", body)
			}
			_, _ = w.Write([]byte(`{"id":"tn_1","status":"active"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/provider/v1/tenants":
			_, _ = w.Write([]byte(`{"items":[{"id":"tn_1","slug":"acme","name":"Acme Networks","status":"active","isolation_model":"pooled","residency":"us"}]}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/provider/v1/tenants/tn_1":
			_, _ = w.Write([]byte(`{"id":"tn_1","status":"active"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/provider/v1/tenants/tn_1/offboard":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected provider request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	d := schema.TestResourceDataRaw(t, resourceProviderTenant().Schema, map[string]any{
		"slug":            "acme",
		"name":            "Acme Networks",
		"isolation_model": "pooled",
		"residency":       "us",
	})
	meta := testClient(srv.URL, "", "provider-token")
	assertNoDiagnostics(t, createProviderTenant(context.Background(), d, meta))
	if d.Id() != "tn_1" {
		t.Fatalf("create id = %q, want tn_1", d.Id())
	}
	assertNoDiagnostics(t, readProviderTenant(context.Background(), d, meta))
	assertNoDiagnostics(t, updateProviderTenant(context.Background(), d, meta))
	assertNoDiagnostics(t, providerTenantAction("offboard")(context.Background(), d, meta))
	if d.Id() != "" {
		t.Fatalf("offboard should clear id, got %q", d.Id())
	}
}

func TestAPIResourceGenericTenantScopedLifecycle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthHeaders(t, r, "tenant-a", "token-a")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/slos":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode SLO body: %v", err)
			}
			if body["name"] != "gold" || body["objective"] != float64(0.999) {
				t.Fatalf("wrong SLO body: %#v", body)
			}
			_, _ = w.Write([]byte(`{"id":"slo-1","status":"ok"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/slos/slo-1":
			_, _ = w.Write([]byte(`{"id":"slo-1","name":"gold","status":"ok"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/slos/slo-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected generic request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	invalid := schema.TestResourceDataRaw(t, resourceAPIResource().Schema, map[string]any{
		"method": "POST",
		"path":   "/v1/slos",
		"body":   "{bad-json",
	})
	if diags := createAPIResource(context.Background(), invalid, testClient(srv.URL, "tenant-a", "token-a")); !diags.HasError() {
		t.Fatalf("invalid JSON should return diagnostics")
	}

	d := schema.TestResourceDataRaw(t, resourceAPIResource().Schema, map[string]any{
		"method":      "POST",
		"path":        "/v1/slos",
		"body":        `{"name":"gold","objective":0.999}`,
		"read_path":   "/v1/slos/{id}",
		"delete_path": "/v1/slos/{id}",
	})
	meta := testClient(srv.URL, "tenant-a", "token-a")
	assertNoDiagnostics(t, createAPIResource(context.Background(), d, meta))
	if d.Id() != "slo-1" {
		t.Fatalf("create id = %q, want slo-1", d.Id())
	}
	if got := d.Get("response_json").(string); !strings.Contains(got, `"status":"ok"`) {
		t.Fatalf("response_json not recorded: %q", got)
	}
	assertNoDiagnostics(t, readAPIResource(context.Background(), d, meta))
	assertNoDiagnostics(t, deleteAPIResource(context.Background(), d, meta))
	if d.Id() != "" {
		t.Fatalf("delete should clear id, got %q", d.Id())
	}
}

func testClient(baseURL, tenant, token string) *client {
	return &client{
		baseURL: strings.TrimRight(baseURL, "/"),
		tenant:  tenant,
		token:   token,
		hc:      crypto.HardenedHTTPClient(0),
	}
}

func assertAuthHeaders(t *testing.T, r *http.Request, tenant, token string) {
	t.Helper()
	if got := r.Header.Get("X-Probectl-Tenant"); got != tenant {
		t.Fatalf("tenant header = %q, want %q", got, tenant)
	}
	if got, want := r.Header.Get("Authorization"), "Bearer "+token; got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
}

func assertNoDiagnostics(t *testing.T, diags interface{ HasError() bool }) {
	t.Helper()
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
}

// TestAlertRouteTrapRuleCRUD: a type = "trap" rule (D-61) posts its trap
// block and none of the metric-rule fields, reads the stored match back, and
// the server's leading-dot OIDs do not diff against configuration without one.
func TestAlertRouteTrapRuleCRUD(t *testing.T) {
	var created, updated map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthHeaders(t, r, "tenant-a", "token-a")
		w.Header().Set("Content-Type", "application/json")
		decode := func() map[string]any {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			return body
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/alerts":
			created = decode()
			_, _ = w.Write([]byte(`{"id":"rule-1","type":"trap"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/alerts/rule-1":
			_, _ = w.Write([]byte(`{"id":"rule-1","name":"uplink down","type":"trap","metric":"probectl_device_trap",
				"comparison":"gte","threshold":1,"severity":"critical","enabled":true,
				"trap":{"trap_oid":".1.3.6.1.6.3.1.1.5.3","clear_trap_oid":".1.3.6.1.6.3.1.1.5.4",
				        "varbind_oid":".1.3.6.1.2.1.2.2.1.1.3","varbind_value":"3","hold_seconds":600}}`))
		case r.Method == http.MethodPut && r.URL.Path == "/v1/alerts/rule-1":
			updated = decode()
			_, _ = w.Write([]byte(`{"id":"rule-1"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/alerts/rule-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	res := resourceAlertRoute()
	d := schema.TestResourceDataRaw(t, res.Schema, map[string]any{
		"name": "uplink down", "type": "trap", "severity": "critical",
		"trap": []any{map[string]any{
			"trap_oid": "1.3.6.1.6.3.1.1.5.3", "clear_trap_oid": "1.3.6.1.6.3.1.1.5.4",
			"varbind_oid": "1.3.6.1.2.1.2.2.1.1.3", "varbind_value": "3", "hold_seconds": 600,
		}},
		"channel": []any{map[string]any{"type": "webhook", "url": "https://hooks.example/traps", "secret": "s"}},
	})
	meta := testClient(srv.URL, "tenant-a", "token-a")
	assertNoDiagnostics(t, createAlertRoute(context.Background(), d, meta))
	if d.Id() != "rule-1" {
		t.Fatalf("create set id %q", d.Id())
	}
	trap, _ := created["trap"].(map[string]any)
	if created["type"] != "trap" || trap["trap_oid"] != "1.3.6.1.6.3.1.1.5.3" || trap["clear_trap_oid"] != "1.3.6.1.6.3.1.1.5.4" ||
		trap["varbind_value"] != "3" || trap["hold_seconds"] != float64(600) || trap["device"] != nil {
		t.Fatalf("wrong trap create body: %#v", created)
	}
	for _, k := range []string{"metric", "comparison", "threshold", "window", "sensitivity", "match"} {
		if _, ok := created[k]; ok {
			t.Fatalf("a trap rule body carries the metric-rule field %q: %#v", k, created)
		}
	}
	assertNoDiagnostics(t, readAlertRoute(context.Background(), d, meta))
	if got := d.Get("trap.0.trap_oid"); got != ".1.3.6.1.6.3.1.1.5.3" {
		t.Fatalf("read trap_oid = %v", got)
	}
	if d.Get("trap.0.hold_seconds") != 600 || d.Get("trap.0.varbind_oid") != ".1.3.6.1.2.1.2.2.1.1.3" {
		t.Fatalf("read trap block = %v", d.Get("trap"))
	}
	if d.Get("metric") != "" || d.Get("comparison") != "gt" {
		t.Fatalf("read copied the server-fixed metric/comparison into state: metric=%v comparison=%v", d.Get("metric"), d.Get("comparison"))
	}
	oidSchema := trapMatchSchema().Schema["trap_oid"]
	if !oidSchema.DiffSuppressFunc("trap.0.trap_oid", ".1.3.6.1.6.3.1.1.5.3", "1.3.6.1.6.3.1.1.5.3", d) ||
		oidSchema.DiffSuppressFunc("trap.0.trap_oid", ".1.3.6.1.6.3.1.1.5.3", ".1.3.6.1.6.3.1.1.5.4", d) {
		t.Fatal("trap OIDs must compare with and without the leading dot, and only then")
	}
	assertNoDiagnostics(t, updateAlertRoute(context.Background(), d, meta))
	if updated["type"] != "trap" || updated["trap"] == nil {
		t.Fatalf("wrong trap update body: %#v", updated)
	}
	assertNoDiagnostics(t, deleteByPath("/v1/alerts/{id}")(context.Background(), d, meta))
}

func TestAlertRouteMetricRuleBodyUnchanged(t *testing.T) {
	d := schema.TestResourceDataRaw(t, resourceAlertRoute().Schema, map[string]any{
		"name": "packet loss", "metric": "probectl_probe_loss_ratio", "comparison": "gt", "threshold": 0.05,
	})
	body := alertBody(d)
	if body["metric"] != "probectl_probe_loss_ratio" || body["type"] != "threshold" || body["comparison"] != "gt" {
		t.Fatalf("threshold body = %#v", body)
	}
	if _, ok := body["trap"]; ok {
		t.Fatalf("a threshold rule body carries a trap match: %#v", body)
	}
}
