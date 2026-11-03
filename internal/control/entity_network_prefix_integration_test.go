// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestPrefixNetworkRESTAndMCPPreserveOwnedIdentityAndCurrentContextPolicy(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	ctx := t.Context()
	a, b := freshTenant(t, db, "prefix-api-a"), freshTenant(t, db, "prefix-api-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Error(err)
		}
	})
	contextID, sharedID := uuid(t), uuid(t)
	for _, tenant := range []string{a, b} {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'West DC','Private')`, tenant, contextID, uuid(t), uuid(t)); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'prefix','10.2.0.0/24')`, tenant, contextID, sharedID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	h := srv.Handler()
	path := "/v1/entities/" + sharedID + "/network-prefix"
	body := func(value any) map[string]any {
		return map[string]any{"context_id": contextID, "network_prefix": value}
	}
	decode := func(rec *httptest.ResponseRecorder, status int) entity.Record {
		t.Helper()
		var row entity.Record
		if rec.Code != status || json.Unmarshal(rec.Body.Bytes(), &row) != nil {
			t.Fatalf("entity response: %d %s", rec.Code, rec.Body.String())
		}
		return row
	}
	for lane, tenant := range []string{a, b} {
		network := []string{"10.2.0.129/25", "2001:db8:2::1/48"}[lane]
		canonical := []string{"10.2.0.128/25", "2001:db8:2::/48"}[lane]
		row := decode(apiReq(t, h, http.MethodPut, path, tenant, body(network)), http.StatusOK)
		if row.ID != sharedID || row.Scope.TenantID != tenant || row.Scope.ContextID != contextID || row.NetworkPrefix != canonical {
			t.Fatal("set changed identity or crossed equal tenant IDs")
		}
		got := decode(apiReq(t, h, http.MethodGet, "/v1/entities/"+sharedID+"?context_id="+contextID, tenant, nil), http.StatusOK)
		if got.NetworkPrefix != canonical {
			t.Fatal("read omitted explicit prefix")
		}
		page := apiReq(t, h, http.MethodGet, "/v1/entities?context_id="+contextID, tenant, nil)
		var list entity.Page
		if page.Code != http.StatusOK || json.Unmarshal(page.Body.Bytes(), &list) != nil || len(list.Items) != 1 || list.Items[0].NetworkPrefix != canonical {
			t.Fatalf("list lost typed range: %d %s", page.Code, page.Body.String())
		}
	}
	created := decode(apiReq(t, h, http.MethodPost, "/v1/entities", a, map[string]string{"context_id": contextID, "kind": "prefix", "label": "unrelated label", "network_prefix": "192.0.2.129/25"}), http.StatusCreated)
	if created.NetworkPrefix != "192.0.2.128/25" || created.ID == sharedID {
		t.Fatal("create did not persist the explicit range on a new ID")
	}
	for _, input := range []map[string]any{body(nil), {"context_id": contextID}, body("192.0.2.1"), body("bad.test/24"), body(strings.Repeat("x", 129))} {
		if rec := apiReq(t, h, http.MethodPut, path, a, input); rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid prefix accepted: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := apiReq(t, h, http.MethodPost, "/v1/entities", a, map[string]string{"context_id": contextID, "kind": "device", "label": "edge", "network_prefix": "10.2.0.0/24"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("device accepted network: %d", rec.Code)
	}
	device := decode(apiReq(t, h, http.MethodPost, "/v1/entities", a, map[string]string{"context_id": contextID, "kind": "device", "label": "edge"}), http.StatusCreated)
	if rec := apiReq(t, h, http.MethodPut, path, a, map[string]string{"context_id": uuid(t), "network_prefix": "10.2.0.0/24"}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown context entered network update: %d", rec.Code)
	}
	for _, deniedPath := range []string{"/v1/entities/" + created.ID + "/network-prefix", "/v1/entities/" + device.ID + "/network-prefix"} {
		tenant := a
		if strings.Contains(deniedPath, created.ID) {
			tenant = b
		}
		if rec := apiReq(t, h, http.MethodPut, deniedPath, tenant, body("10.2.0.0/24")); rec.Code != http.StatusNotFound {
			t.Fatalf("foreign/wrong-kind update: %d %s", rec.Code, rec.Body.String())
		}
	}
	for _, tc := range []struct{ method, path, grant string }{{http.MethodPut, path, "agent.write"}, {http.MethodGet, "/v1/entities/" + sharedID + "?context_id=" + contextID, "entities.read"}} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"context_id":"`+contextID+`","network_prefix":""}`))
		req.Header.Set("X-Probectl-Tenant", a)
		req.Header.Set(testWithholdPermissionsHeader, tc.grant)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("missing %s reached network path: %d", tc.grant, rec.Code)
		}
	}
	backend := mcpEntityBackend{pool: db.Pool(), policyLoader: srv.abac.policies}
	writer := func(tenant string) *auth.Principal {
		return &auth.Principal{TenantID: tenant, UserID: "prefix-operator", Permissions: map[string]bool{"agent.write": true, "entities.read": true}}
	}
	value := "198.51.100.129/25"
	item, err := backend.EntityNetworkPrefixSet(ctx, writer(a), mcp.EntityNetworkPrefixInput{ContextID: contextID, ID: sharedID, NetworkPrefix: &value})
	if err != nil || item.ID != sharedID || item.NetworkPrefix != "198.51.100.128/25" {
		t.Fatalf("MCP set: %+v %v", item, err)
	}
	read, err := backend.EntityGet(ctx, writer(a), mcp.EntityGetInput{ContextID: contextID, ID: sharedID})
	if err != nil || read.NetworkPrefix != item.NetworkPrefix {
		t.Fatal("MCP read lost network range")
	}
	if _, err := backend.EntityNetworkPrefixSet(ctx, writer(b), mcp.EntityNetworkPrefixInput{ContextID: contextID, ID: created.ID, NetworkPrefix: &value}); err == nil {
		t.Fatal("MCP wrote a foreign canonical prefix")
	}
	if _, err := backend.EntityNetworkPrefixSet(ctx, writer(a), mcp.EntityNetworkPrefixInput{ContextID: contextID, ID: sharedID}); err == nil {
		t.Fatal("MCP omitted network field implicitly cleared metadata")
	}
	srv.abac = &abacCache{load: func(_ context.Context, tenant string) ([]auth.Policy, error) {
		if tenant != a {
			return nil, nil
		}
		return []auth.Policy{{Name: "deny prefix writes", Enabled: true, Effect: auth.PolicyDeny, Permission: "agent.write", Resource: map[string]string{"site_label": "West DC"}}}, nil
	}}
	backend.policyLoader = srv.abac.policies
	if rec := apiReq(t, h, http.MethodPut, path, a, body("")); rec.Code != http.StatusForbidden {
		t.Fatalf("REST context deny bypassed: %d", rec.Code)
	}
	if _, err := backend.EntityNetworkPrefixSet(ctx, writer(a), mcp.EntityNetworkPrefixInput{ContextID: contextID, ID: sharedID, NetworkPrefix: &value}); err == nil {
		t.Fatal("MCP bypassed current context deny")
	}
	if rec := apiReq(t, h, http.MethodPut, path, b, body("")); rec.Code != http.StatusOK {
		t.Fatalf("other tenant inherited policy: %d", rec.Code)
	}
	srv.abac = &abacCache{load: func(context.Context, string) ([]auth.Policy, error) { return nil, nil }}
	backend.policyLoader = srv.abac.policies
	// A real failed audit INSERT must roll the preceding metadata UPDATE back
	// on both request paths. The constraint targets only this owned fixture.
	if _, err := db.Pool().Exec(ctx, `ALTER TABLE audit_events ADD CONSTRAINT probectl_qa_beta_prefix_audit CHECK (action <> 'entity.network_prefix.updated' OR tenant_id::text <> '`+a+`') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	dropFault := func() {
		t.Helper()
		if _, err := db.Pool().Exec(context.Background(), `ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS probectl_qa_beta_prefix_audit`); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(dropFault)
	if rec := apiReq(t, h, http.MethodPut, path, a, body("203.0.113.0/24")); rec.Code < 500 {
		t.Fatalf("REST accepted failed audit: %d", rec.Code)
	}
	value = "203.0.113.0/24"
	if _, err := backend.EntityNetworkPrefixSet(ctx, writer(a), mcp.EntityNetworkPrefixInput{ContextID: contextID, ID: sharedID, NetworkPrefix: &value}); err == nil {
		t.Fatal("MCP accepted failed audit")
	}
	if actual := decode(apiReq(t, h, http.MethodGet, "/v1/entities/"+sharedID+"?context_id="+contextID, a, nil), http.StatusOK); actual.NetworkPrefix != "198.51.100.128/25" {
		t.Fatal("failed audit committed metadata")
	}
	dropFault()
	cleared := decode(apiReq(t, h, http.MethodPut, path, a, body("")), http.StatusOK)
	if cleared.ID != sharedID || cleared.NetworkPrefix != "" {
		t.Fatal("explicit clear recreated the subject")
	}
	// Inspect the actual audit projection: the CIDR itself is not logged.
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		var count, leaked int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE data::text LIKE '%198.51.100%' OR data::text LIKE '%10.2.%' OR data::text LIKE '%203.0.113%') FROM audit_events WHERE tenant_id=$1 AND action='entity.network_prefix.updated' AND target=$2`, a, sharedID).Scan(&count, &leaked); err != nil {
			return err
		}
		if count != 3 || leaked != 0 {
			t.Fatalf("network mutation audit count=%d leaked=%d", count, leaked)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
