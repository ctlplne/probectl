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
	"github.com/ctlplne/probectl/internal/tags"
)

func TestTagRuleAPIEnforcesTenantContextAndPermissions(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "tag-rule-api-a"), freshTenant(t, db, "tag-rule-api-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove tag rule API fixture tenants: %v", err)
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
	contextFor := func(tenant string) string {
		t.Helper()
		rec := request(http.MethodPost, "/v1/entity-contexts", tenant,
			`{"site_label":"site","vrf_label":"vrf"}`, "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("create context tenant %s: %d %s", tenant, rec.Code, rec.Body.String())
		}
		var out struct {
			ContextID string `json:"context_id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.ContextID
	}
	contextA, contextB := contextFor(a), contextFor(b)
	createTag := request(http.MethodPost, "/v1/tags", a, `{"key":"customer"}`, "")
	if createTag.Code != http.StatusCreated {
		t.Fatalf("create tag: %d %s", createTag.Code, createTag.Body.String())
	}
	var definition tags.Definition
	if err := json.Unmarshal(createTag.Body.Bytes(), &definition); err != nil {
		t.Fatal(err)
	}
	pathA := "/v1/entity-contexts/" + contextA + "/tag-rules"
	pathB := "/v1/entity-contexts/" + contextB + "/tag-rules"
	input := `{"tag_id":"` + definition.ID + `","target_kind":"exporter",` +
		`"match_kind":"cidr","address_side":"exporter",` +
		`"cidr":"10.42.0.0/16","value":"blue"}`
	created := request(http.MethodPost, pathA, a, input, "")
	if created.Code != http.StatusCreated {
		t.Fatalf("create rule: %d %s", created.Code, created.Body.String())
	}
	var rule tags.Rule
	if err := json.Unmarshal(created.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.ID == "" || rule.TenantID != a || rule.ContextID != contextA {
		t.Fatalf("rule escaped tenant/context: %+v", rule)
	}
	for _, tc := range []struct {
		method, path, tenant, body, withheld string
		want                                 int
	}{
		{http.MethodGet, pathA, a, "", "tags.read", http.StatusForbidden},
		{http.MethodPost, pathA, a, input, "tags.write", http.StatusForbidden},
		{http.MethodPost, pathB, b, input, "", http.StatusNotFound},
		{http.MethodGet, pathA, b, "", "", http.StatusNotFound},
		{http.MethodDelete, pathA + "/" + rule.ID, b, "", "", http.StatusNotFound},
		{http.MethodPost, pathA, a, strings.Replace(input, "10.42.0.0/16", "10.42.0.1/16", 1), "", http.StatusBadRequest},
	} {
		rec := request(tc.method, tc.path, tc.tenant, tc.body, tc.withheld)
		if rec.Code != tc.want {
			t.Fatalf("%s %s tenant=%s withheld=%s: %d %s, want %d",
				tc.method, tc.path, tc.tenant, tc.withheld, rec.Code, rec.Body.String(), tc.want)
		}
	}
	for _, tc := range []struct {
		tenant, path string
		want         int
	}{{a, pathA, 1}, {b, pathB, 0}} {
		rec := request(http.MethodGet, tc.path+"?limit=1", tc.tenant, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list %s rules: %d %s", tc.tenant, rec.Code, rec.Body.String())
		}
		var page struct {
			Items []tags.Rule `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != tc.want {
			t.Fatalf("tenant %s saw wrong rules: %+v", tc.tenant, page)
		}
	}
	updated := request(http.MethodPut, pathA+"/"+rule.ID, a,
		strings.Replace(input, `"value":"blue"`, `"value":"green"`, 1), "")
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"value":"green"`) {
		t.Fatalf("update rule: %d %s", updated.Code, updated.Body.String())
	}
	deleted := request(http.MethodDelete, pathA+"/"+rule.ID, a, "", "")
	if deleted.Code != http.StatusNoContent || deleted.Body.Len() != 0 {
		t.Fatalf("delete rule: %d %s", deleted.Code, deleted.Body.String())
	}

	entityCreated := request(http.MethodPost, "/v1/entities", a,
		`{"context_id":"`+contextA+`","kind":"device","label":"router"}`, "")
	if entityCreated.Code != http.StatusCreated {
		t.Fatalf("create canonical tag subject: %d %s", entityCreated.Code,
			entityCreated.Body.String())
	}
	var subject struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(entityCreated.Body.Bytes(), &subject); err != nil {
		t.Fatal(err)
	}
	assignPathA := "/v1/entity-contexts/" + contextA + "/tag-assignments"
	assignPathB := "/v1/entity-contexts/" + contextB + "/tag-assignments"
	assignmentInput := `{"tag_id":"` + definition.ID + `","target_kind":"device",` +
		`"target_id":"` + subject.ID + `","value":"blue"}`
	assignmentCreated := request(http.MethodPost, assignPathA, a, assignmentInput, "")
	if assignmentCreated.Code != http.StatusCreated {
		t.Fatalf("create manual tag assignment: %d %s", assignmentCreated.Code,
			assignmentCreated.Body.String())
	}
	var assignment struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
		TargetID string `json:"target_id"`
	}
	if err := json.Unmarshal(assignmentCreated.Body.Bytes(), &assignment); err != nil {
		t.Fatal(err)
	}
	if assignment.ID == "" || assignment.TenantID != a || assignment.TargetID != subject.ID {
		t.Fatalf("manual assignment escaped scope: %+v", assignment)
	}
	for _, tc := range []struct {
		tenant, path string
		want         int
	}{{a, assignPathA, 1}, {b, assignPathB, 0}} {
		rec := request(http.MethodGet, tc.path+"?limit=1", tc.tenant, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list %s assignments: %d %s", tc.tenant, rec.Code, rec.Body.String())
		}
		var page struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != tc.want ||
			(tc.tenant == a && page.Items[0].ID != assignment.ID) {
			t.Fatalf("tenant %s saw wrong assignments: %+v", tc.tenant, page)
		}
	}
	readBackend := mcpTagBackend{pool: db.Pool(), policyLoader: func(context.Context, string) ([]auth.Policy, error) {
		return nil, nil
	}}
	for _, tc := range []struct {
		tenant, contextID string
		want              int
	}{{a, contextA, 1}, {b, contextB, 0}} {
		principal := &auth.Principal{TenantID: tc.tenant, UserID: "tag-reader",
			Permissions: map[string]bool{permTagsRead: true}}
		definitions, err := readBackend.TagDefinitionList(context.Background(), principal)
		if err != nil || len(definitions.Items) != tc.want {
			t.Fatalf("MCP tag definitions tenant %s: %+v %v", tc.tenant, definitions, err)
		}
		assigned, err := readBackend.TagAssignmentList(context.Background(), principal,
			mcp.TagContextListInput{ContextID: tc.contextID, Limit: 1})
		if err != nil || len(assigned.Items) != tc.want {
			t.Fatalf("MCP assigned tags tenant %s: %+v %v", tc.tenant, assigned, err)
		}
	}
	foreignPrincipal := &auth.Principal{TenantID: b, UserID: "tag-reader",
		Permissions: map[string]bool{permTagsRead: true}}
	if _, err := readBackend.TagAssignmentList(context.Background(), foreignPrincipal,
		mcp.TagContextListInput{ContextID: contextA}); err == nil {
		t.Fatal("MCP tag read accepted another tenant's routing context")
	}
	for _, tc := range []struct {
		method, path, tenant, body, withheld string
		want                                 int
	}{
		{http.MethodGet, assignPathA, a, "", "tags.read", http.StatusForbidden},
		{http.MethodPost, assignPathA, a, assignmentInput, "tags.write", http.StatusForbidden},
		{http.MethodPost, assignPathB, b, assignmentInput, "", http.StatusNotFound},
		{http.MethodGet, assignPathA, b, "", "", http.StatusNotFound},
		{http.MethodDelete, assignPathA + "/" + assignment.ID, b, "", "", http.StatusNotFound},
		{http.MethodPost, assignPathA, a, assignmentInput, "", http.StatusConflict},
	} {
		rec := request(tc.method, tc.path, tc.tenant, tc.body, tc.withheld)
		if rec.Code != tc.want {
			t.Fatalf("%s %s tenant=%s withheld=%s: %d %s, want %d",
				tc.method, tc.path, tc.tenant, tc.withheld, rec.Code, rec.Body.String(), tc.want)
		}
	}
	assignmentUpdated := request(http.MethodPut, assignPathA+"/"+assignment.ID, a,
		strings.Replace(assignmentInput, `"value":"blue"`, `"value":"green"`, 1), "")
	if assignmentUpdated.Code != http.StatusOK ||
		!strings.Contains(assignmentUpdated.Body.String(), `"value":"green"`) {
		t.Fatalf("update manual assignment: %d %s", assignmentUpdated.Code,
			assignmentUpdated.Body.String())
	}
	assignmentDeleted := request(http.MethodDelete, assignPathA+"/"+assignment.ID, a, "", "")
	if assignmentDeleted.Code != http.StatusNoContent || assignmentDeleted.Body.Len() != 0 {
		t.Fatalf("delete manual assignment: %d %s", assignmentDeleted.Code,
			assignmentDeleted.Body.String())
	}
}
