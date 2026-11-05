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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestTagCapacityPublicVocabularyKeepsEveryOwnedDefinition(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	tenants := []string{freshTenant(t, db, "tag-cap-api-a"), freshTenant(t, db, "tag-cap-api-b")}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	for lane, tenant := range tenants {
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) SELECT $1,('10000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid,$2||lpad(i::text,3,'0') FROM generate_series(1,128) AS g(i)`, tenant, fmt.Sprintf("lane_%d_", lane))
			return err
		})
		if err != nil {
			t.Fatal("clean larger vocabulary fixture", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/tags", strings.NewReader(fmt.Sprintf(`{"key":"lane_%d_129"}`, lane)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Probectl-Tenant", tenant)
		out := httptest.NewRecorder()
		srv.Handler().ServeHTTP(out, req)
		if out.Code != http.StatusCreated {
			t.Fatal("above-former public definition write refused", out.Code)
		}
	}
	for lane, tenant := range tenants {
		prefix := fmt.Sprintf("lane_%d_", lane)
		for _, path := range []string{"/v1/tags", "/v1/explorer/schema"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("X-Probectl-Tenant", tenant)
			out := httptest.NewRecorder()
			srv.Handler().ServeHTTP(out, req)
			if out.Code != http.StatusOK {
				t.Fatal("above-former public vocabulary refused", path, out.Code)
			}
			if path == "/v1/tags" {
				var result struct {
					Items []tags.Definition `json:"items"`
				}
				if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if len(result.Items) != 129 {
					t.Fatal("public vocabulary truncated", len(result.Items))
				}
				for _, item := range result.Items {
					if item.TenantID != tenant || !strings.HasPrefix(item.Key, prefix) {
						t.Fatal("public vocabulary crossed tenants")
					}
				}
			} else {
				var result struct {
					Flow struct {
						Fields []flow.QueryField `json:"fields"`
					} `json:"flow"`
				}
				if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				seen := map[string]bool{}
				for _, field := range result.Flow.Fields {
					if strings.HasPrefix(field.Name, "tag.") {
						seen[field.Name] = true
					}
				}
				if len(seen) != 129*7 {
					t.Fatal("expanded public vocabulary truncated", len(seen))
				}
				for i := 1; i <= 129; i++ {
					for _, qualifier := range []string{"", "device.", "agent.", "in_interface.", "out_interface.", "src_prefix.", "dst_prefix."} {
						if !seen[fmt.Sprintf("tag.%s%s%03d", qualifier, prefix, i)] {
							t.Fatal("owned expanded field missing")
						}
					}
				}
			}
		}
		backend := mcpTagBackend{pool: db.Pool(), flowStore: srv.flowStore}
		result, err := backend.TagDefinitionList(t.Context(), &auth.Principal{TenantID: tenant})
		if err != nil || len(result.Items) != 129 {
			t.Fatal("MCP backend vocabulary truncated", len(result.Items), err)
		}
		for _, item := range result.Items {
			if !strings.HasPrefix(item.Key, prefix) {
				t.Fatal("MCP backend vocabulary crossed tenants")
			}
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/explorer/schema", nil)
		req.Header.Set("X-Probectl-Tenant", tenant)
		req.Header.Set(testWithholdPermissionsHeader, permTagsRead)
		out := httptest.NewRecorder()
		srv.Handler().ServeHTTP(out, req)
		if out.Code != http.StatusOK || strings.Contains(out.Body.String(), "tag."+prefix) {
			t.Fatal("larger vocabulary changed tags.read boundary", out.Code)
		}
	}
}
