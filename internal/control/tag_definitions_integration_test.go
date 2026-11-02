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

	"github.com/ctlplne/probectl/internal/tags"
)

func TestTagDefinitionAPIEnforcesTenantAndPermission(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "tag-api-a"), freshTenant(t, db, "tag-api-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove tag API fixture tenants: %v", err)
		}
	})
	h := srv.Handler()
	request := func(method, path, tenant, body, withheld string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-Probectl-Tenant", tenant)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if withheld != "" {
			req.Header.Set(testWithholdPermissionsHeader, withheld)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	create := request(http.MethodPost, "/v1/tags", a, `{"key":"customer"}`, "")
	if create.Code != http.StatusCreated {
		t.Fatalf("create tag: %d %s", create.Code, create.Body.String())
	}
	var item tags.Definition
	if err := json.Unmarshal(create.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.TenantID != a || item.ID == "" || item.Key != "customer" {
		t.Fatalf("created definition escaped tenant or shape: %+v", item)
	}
	for _, tc := range []struct {
		method, path, tenant, body, withheld string
		want                                 int
	}{
		{http.MethodGet, "/v1/tags", a, "", "tags.read", http.StatusForbidden},
		{http.MethodPost, "/v1/tags", a, `{"key":"other"}`, "tags.write", http.StatusForbidden},
		{http.MethodPost, "/v1/tags", a, `{"key":"tenant_id"}`, "", http.StatusBadRequest},
		{http.MethodPost, "/v1/tags", a, `{"key":"customer"}`, "", http.StatusConflict},
		{http.MethodPut, "/v1/tags/" + item.ID, b, `{"key":"foreign"}`, "", http.StatusNotFound},
		{http.MethodDelete, "/v1/tags/" + item.ID, b, "", "", http.StatusNotFound},
		{http.MethodPut, "/v1/tags/invalid", a, `{"key":"other"}`, "", http.StatusBadRequest},
	} {
		rec := request(tc.method, tc.path, tc.tenant, tc.body, tc.withheld)
		if rec.Code != tc.want {
			t.Fatalf("%s %s tenant=%s withheld=%s: %d %s, want %d",
				tc.method, tc.path, tc.tenant, tc.withheld, rec.Code, rec.Body.String(), tc.want)
		}
	}
	for _, tenant := range []string{a, b} {
		rec := request(http.MethodGet, "/v1/tags", tenant, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list tenant %s: %d %s", tenant, rec.Code, rec.Body.String())
		}
		var page struct {
			Items []tags.Definition `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if tenant == a && (len(page.Items) != 1 || page.Items[0] != item) {
			t.Fatalf("tenant A tag list changed: %+v", page)
		}
		if tenant == b && len(page.Items) != 0 {
			t.Fatalf("tenant B saw tenant A tag: %+v", page)
		}
	}
	rename := request(http.MethodPut, "/v1/tags/"+item.ID, a, `{"key":"customer_new"}`, "")
	if rename.Code != http.StatusOK || !strings.Contains(rename.Body.String(), `"key":"customer_new"`) {
		t.Fatalf("rename tag: %d %s", rename.Code, rename.Body.String())
	}
	removed := request(http.MethodDelete, "/v1/tags/"+item.ID, a, "", "")
	if removed.Code != http.StatusNoContent || removed.Body.Len() != 0 {
		t.Fatalf("delete tag: %d %s", removed.Code, removed.Body.String())
	}
	if rec := request(http.MethodGet, "/v1/tags", a, "", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"items":[]`) {
		t.Fatalf("deleted tag remained visible: %d %s", rec.Code, rec.Body.String())
	}
}
