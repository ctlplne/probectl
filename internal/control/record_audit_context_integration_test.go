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
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestRecordAuditCarriesRequestContext is the AUD-10 follow-up: explicit domain
// audit events (role binds, token mints, agent revokes, key rotations — ~60
// routes that append via recordAudit) must carry the same "from where" fields
// as route-level access events. The finding's remediation names "every
// route-level AND explicit audit event".
func TestRecordAuditCarriesRequestContext(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{Email: "aud10-explicit@example.com"})
	ctx := context.Background()

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("User-Agent", "AUD10-explicit-UA/2.0")
	req = req.WithContext(logging.WithRequestID(req.Context(), "aud10-explicit-rid"))

	action := fmt.Sprintf("test.explicit.%d", time.Now().UnixNano())
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.DefaultTenantID), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		return srv.recordAudit(ctx, sc, req, action, "target-1", map[string]any{"k": "v"})
	}); err != nil {
		t.Fatalf("recordAudit: %v", err)
	}

	var raw string
	if err := db.Pool().QueryRow(ctx,
		`SELECT data::text FROM audit_events WHERE tenant_id = $1::uuid AND action = $2`,
		tenancy.DefaultTenantID.String(), action).Scan(&raw); err != nil {
		t.Fatalf("read event: %v", err)
	}
	m := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, f := range []string{"ip", "user_agent", "request_id", "outcome"} {
		if v, ok := m[f]; !ok || v == "" {
			t.Errorf("AUD-10: explicit audit event missing %q (data=%v)", f, m)
		}
	}
	if m["outcome"] != "success" {
		t.Errorf("AUD-10: explicit event outcome = %v, want success", m["outcome"])
	}
	if m["request_id"] != "aud10-explicit-rid" {
		t.Errorf("AUD-10: explicit event request_id = %v, want the request's id", m["request_id"])
	}
	if m["k"] != "v" {
		t.Errorf("AUD-10: caller data was dropped: %v", m)
	}
	if uaVal, _ := m["user_agent"].(string); uaVal == "AUD10-explicit-UA/2.0" {
		t.Error("AUD-10: explicit event stored the raw user agent instead of a hash")
	}
}
