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

	uuidx "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/store"
)

func TestTagAPIAcceptsFullEscapedUnicodeValueOnlyInAuthenticatedTenant(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "tag-value-api-a"), freshTenant(t, db, "tag-value-api-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Error(err)
		}
	})
	contextID, tagID := uuidx.NewString(), uuidx.NewString()
	for _, tenant := range []string{a, b} {
		for _, statement := range []string{
			`INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$2,$2,'site','vrf')`,
			`INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$2,'device','router')`,
		} {
			if _, err := db.Pool().Exec(context.Background(), statement, tenant, contextID); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.Pool().Exec(context.Background(), `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'customer')`, tenant, tagID); err != nil {
			t.Fatal(err)
		}
	}
	// Both lanes deliberately share the same compound subject identifiers.
	deviceID := contextID
	path := "/v1/entity-contexts/" + contextID + "/tag-assignments"
	for _, row := range []struct{ tenant, escaped, value string }{{a, `\ud83c\udf10`, "🌐"}, {b, `\ud83e\udded`, "🧭"}} {
		body := fmt.Sprintf(`{"tag_id":%q,"target_kind":"device","target_id":%q,"value":"%s"}`, tagID, deviceID, strings.Repeat(row.escaped, 24000))
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Probectl-Tenant", row.tenant)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		var assignment store.TagAssignmentRecord
		if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &assignment) != nil || assignment.TenantID != row.tenant || assignment.Value != strings.Repeat(row.value, 24000) {
			t.Fatalf("full escaped Unicode API value refused or crossed tenant: status=%d response_bytes=%d", rec.Code, rec.Body.Len())
		}
		page := apiReq(t, srv.Handler(), http.MethodGet, path, row.tenant, nil)
		var out struct {
			Items []store.TagAssignmentRecord `json:"items"`
		}
		if page.Code != http.StatusOK || json.Unmarshal(page.Body.Bytes(), &out) != nil || len(out.Items) != 1 || out.Items[0].Value != assignment.Value {
			t.Fatalf("long value tenant page was truncated or widened: status=%d", page.Code)
		}
	}
	oversized := manualTagAssignmentRequest{TagID: tagID, TargetKind: "device", TargetID: deviceID, Value: strings.Repeat("x", 24001)}
	if rec := apiReq(t, srv.Handler(), http.MethodPost, path, a, oversized); rec.Code != http.StatusBadRequest {
		t.Fatalf("over-limit metadata value bypassed API validation: %d", rec.Code)
	}
}
