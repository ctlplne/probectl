// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package terraformprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestTenantDataSourcesListAndByID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/provider/v1/tenants" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
		if got := r.Header.Get("X-Probectl-Tenant"); got != "" {
			t.Fatalf("provider-plane data source inherited tenant header %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer provider-token" {
			t.Fatalf("authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"tenant-a","slug":"acme","name":"Acme","status":"active","isolation_model":"pooled","residency":"us","created_at":"2026-07-14T00:00:00Z"},{"id":"tenant-b","slug":"beta","name":"Beta","status":"suspended","isolation_model":"siloed","residency":"eu","created_at":"2026-07-14T01:00:00Z"}]}`))
	}))
	defer srv.Close()
	meta := testClient(srv.URL, "must-not-cross-provider-boundary", "provider-token")

	one := schema.TestResourceDataRaw(t, dataSourceTenant().Schema, map[string]any{"tenant_id": "tenant-b"})
	assertNoDiagnostics(t, readTenantDataSource(context.Background(), one, meta))
	if one.Id() != "tenant-b" || one.Get("slug") != "beta" || one.Get("status") != "suspended" {
		t.Fatalf("tenant lookup state = id:%q slug:%v status:%v", one.Id(), one.Get("slug"), one.Get("status"))
	}

	all := schema.TestResourceDataRaw(t, dataSourceTenants().Schema, nil)
	assertNoDiagnostics(t, readTenantsDataSource(context.Background(), all, meta))
	tenants := all.Get("tenants").([]any)
	if all.Id() == "" || len(tenants) != 2 || tenants[0].(map[string]any)["id"] != "tenant-a" {
		t.Fatalf("tenant list state = id:%q tenants:%#v", all.Id(), tenants)
	}
}

func TestTestDataSourcesListAndByIDStayTenantScoped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthHeaders(t, r, "tenant-a", "token-a")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tests/test-1":
			_, _ = w.Write([]byte(`{"id":"test-1","tenant_id":"tenant-a","name":"edge dns","type":"dns","target":"1.1.1.1","interval_seconds":30,"timeout_seconds":3,"params":{"qtype":"A"},"enabled":true,"created_at":"2026-07-14T00:00:00Z","updated_at":"2026-07-14T01:00:00Z"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tests":
			if got := r.URL.Query().Get("after"); got != "test-0" {
				t.Fatalf("after = %q, want test-0", got)
			}
			if got := r.URL.Query().Get("limit"); got != "25" {
				t.Fatalf("limit = %q, want 25", got)
			}
			_, _ = w.Write([]byte(`{"items":[{"id":"test-1","tenant_id":"tenant-a","name":"edge dns","type":"dns","target":"1.1.1.1","interval_seconds":30,"timeout_seconds":3,"params":{"qtype":"A"},"enabled":true}],"next_cursor":"test-1"}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer srv.Close()
	meta := testClient(srv.URL, "tenant-a", "token-a")

	one := schema.TestResourceDataRaw(t, dataSourceTest().Schema, map[string]any{"test_id": "test-1"})
	assertNoDiagnostics(t, readTestDataSource(context.Background(), one, meta))
	if one.Id() != "test-1" || one.Get("tenant_id") != "tenant-a" || one.Get("name") != "edge dns" {
		t.Fatalf("test lookup state = id:%q tenant:%v name:%v", one.Id(), one.Get("tenant_id"), one.Get("name"))
	}

	page := schema.TestResourceDataRaw(t, dataSourceTests().Schema, map[string]any{"after": "test-0", "limit": 25})
	assertNoDiagnostics(t, readTestsDataSource(context.Background(), page, meta))
	tests := page.Get("tests").([]any)
	if page.Id() == "" || page.Get("next_cursor") != "test-1" || len(tests) != 1 {
		t.Fatalf("test page state = id:%q next:%v tests:%#v", page.Id(), page.Get("next_cursor"), tests)
	}
}

func TestAgentDataSourcesListAndByIDStayTenantScoped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthHeaders(t, r, "tenant-a", "token-a")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents/agent-1":
			_, _ = w.Write([]byte(`{"id":"agent-1","tenant_id":"tenant-a","name":"edge agent","hostname":"edge-1","agent_version":"1.2.3","status":"online","capabilities":["dns","http"],"spiffe_id":"spiffe://probectl/tenant/tenant-a/agent/agent-1","registered_at":"2026-07-14T00:00:00Z","last_seen_at":"2026-07-14T01:00:00Z","created_at":"2026-07-14T00:00:00Z"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			if got := r.URL.Query().Get("after"); got != "agent-0" {
				t.Fatalf("after = %q, want agent-0", got)
			}
			if got := r.URL.Query().Get("limit"); got != "10" {
				t.Fatalf("limit = %q, want 10", got)
			}
			_, _ = w.Write([]byte(`{"items":[{"id":"agent-1","tenant_id":"tenant-a","name":"edge agent","hostname":"edge-1","agent_version":"1.2.3","status":"online","capabilities":["dns","http"]}],"next_cursor":"agent-1"}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	defer srv.Close()
	meta := testClient(srv.URL, "tenant-a", "token-a")

	one := schema.TestResourceDataRaw(t, dataSourceAgent().Schema, map[string]any{"agent_id": "agent-1"})
	assertNoDiagnostics(t, readAgentDataSource(context.Background(), one, meta))
	if one.Id() != "agent-1" || one.Get("tenant_id") != "tenant-a" || one.Get("hostname") != "edge-1" {
		t.Fatalf("agent lookup state = id:%q tenant:%v hostname:%v", one.Id(), one.Get("tenant_id"), one.Get("hostname"))
	}

	page := schema.TestResourceDataRaw(t, dataSourceAgents().Schema, map[string]any{"after": "agent-0", "limit": 10})
	assertNoDiagnostics(t, readAgentsDataSource(context.Background(), page, meta))
	agents := page.Get("agents").([]any)
	if page.Id() == "" || page.Get("next_cursor") != "agent-1" || len(agents) != 1 {
		t.Fatalf("agent page state = id:%q next:%v agents:%#v", page.Id(), page.Get("next_cursor"), agents)
	}
}

func TestByIDDataSourcesFailClosedWhenMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()
	meta := testClient(srv.URL, "tenant-a", "token-a")

	for name, tc := range map[string]struct {
		resource *schema.Resource
		input    map[string]any
		read     schema.ReadContextFunc
	}{
		"test":  {dataSourceTest(), map[string]any{"test_id": "missing"}, readTestDataSource},
		"agent": {dataSourceAgent(), map[string]any{"agent_id": "missing"}, readAgentDataSource},
	} {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, tc.resource.Schema, tc.input)
			if diags := tc.read(context.Background(), d, meta); !diags.HasError() {
				t.Fatal("missing lookup must return diagnostics instead of empty state")
			}
		})
	}
}

func TestTenantScopedDataSourcesRejectResponseTenantMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthHeaders(t, r, "tenant-a", "token-a")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/tests/test-1":
			_, _ = w.Write([]byte(`{"id":"test-1","tenant_id":"tenant-b","name":"foreign","type":"dns"}`))
		case "/v1/tests":
			_, _ = w.Write([]byte(`{"items":[{"id":"test-1","tenant_id":"tenant-b","name":"foreign","type":"dns"}]}`))
		case "/v1/agents/agent-1":
			_, _ = w.Write([]byte(`{"id":"agent-1","tenant_id":"tenant-b","name":"foreign","status":"online","capabilities":[]}`))
		case "/v1/agents":
			_, _ = w.Write([]byte(`{"items":[{"id":"agent-1","tenant_id":"tenant-b","name":"foreign","status":"online","capabilities":[]}]}`))
		default:
			t.Fatalf("unexpected request: %s", r.URL.RequestURI())
		}
	}))
	defer srv.Close()
	meta := testClient(srv.URL, "tenant-a", "token-a")

	cases := map[string]struct {
		resource *schema.Resource
		input    map[string]any
		read     schema.ReadContextFunc
	}{
		"test by id":  {dataSourceTest(), map[string]any{"test_id": "test-1"}, readTestDataSource},
		"test list":   {dataSourceTests(), nil, readTestsDataSource},
		"agent by id": {dataSourceAgent(), map[string]any{"agent_id": "agent-1"}, readAgentDataSource},
		"agent list":  {dataSourceAgents(), nil, readAgentsDataSource},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d := schema.TestResourceDataRaw(t, tc.resource.Schema, tc.input)
			if diags := tc.read(context.Background(), d, meta); !diags.HasError() {
				t.Fatal("cross-tenant response must fail closed")
			}
			if d.Id() != "" {
				t.Fatalf("cross-tenant response wrote Terraform state id %q", d.Id())
			}
		})
	}
}
