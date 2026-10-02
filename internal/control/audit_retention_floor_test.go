// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenantlife"
)

// TestLifecycleRetentionPutRejectsBelowAuditFloor is the AUD-07 regression: a
// tenant admin could shrink audit_retention_days to ~1 day, erasing the audit
// trail within a day or two of SIEM delivery. A deployment compliance floor
// (PROBECTL_AUDIT_RETENTION_MIN) must reject a shorter audit retention with 400.
func TestLifecycleRetentionPutRejectsBelowAuditFloor(t *testing.T) {
	srv := testServer(fakePinger{})
	srv.tenantLife = &fakeTenantLifecycle{policy: tenantlife.RetentionPolicy{}}
	srv.cfg.AuditRetentionMin = 30 * 24 * time.Hour // 30-day floor (D-23)

	// Below the floor → 400, and the lifecycle engine is never asked to set it.
	if rec := lifecycleReq(t, srv, http.MethodPut, "/v1/lifecycle/retention", map[string]any{"audit_retention_days": 1}); rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT audit_retention_days=1 with a 30-day floor = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	// At/above the floor → accepted (not a 400).
	if rec := lifecycleReq(t, srv, http.MethodPut, "/v1/lifecycle/retention", map[string]any{"audit_retention_days": 30}); rec.Code == http.StatusBadRequest {
		t.Fatalf("PUT audit_retention_days=30 (== floor) was rejected: %s", rec.Body.String())
	}
}
