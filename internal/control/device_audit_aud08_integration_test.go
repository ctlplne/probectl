// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
)

// TestDeviceMutationRoutesAuditExplicitAction is the AUD-08 regression: the two
// device mutation routes are declared explicit-mode in the audit-policy matrix
// (device.syslog_ingest / device.config_archive) but their handlers never
// appended the event, so the declared action was promised yet absent from the
// tenant's audit chain. Posting to each route must now land exactly the declared
// action on that tenant's chain — no more, no fewer.
func TestDeviceMutationRoutesAuditExplicitAction(t *testing.T) {
	h, db := setupAPI(t)
	ctx := context.Background()

	tenant, err := store.NewTenants(db.Pool()).Create(
		ctx, fmt.Sprintf("aud08-%d", time.Now().UnixNano()), "AUD-08")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// tenantActions returns the sorted set of audit actions recorded for this
	// fresh tenant. Nothing else writes to it, so the set is exactly what the
	// device mutations appended.
	tenantActions := func(t *testing.T) []string {
		t.Helper()
		rows, err := db.Pool().Query(ctx,
			`SELECT action FROM audit_events WHERE tenant_id = $1::uuid ORDER BY seq`,
			tenant.ID)
		if err != nil {
			t.Fatalf("query audit chain: %v", err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				t.Fatalf("scan action: %v", err)
			}
			out = append(out, a)
		}
		return out
	}

	countAction := func(t *testing.T, action string) int {
		t.Helper()
		var n int
		if err := db.Pool().QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid AND action = $2`,
			tenant.ID, action).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", action, err)
		}
		return n
	}

	// 1. POST /v1/device/syslog → exactly one device.syslog_ingest event.
	rec := apiReq(t, h, http.MethodPost, "/v1/device/syslog", tenant.ID,
		map[string]any{"device": "edge-a", "raw": "<134>Jul  2 12:35:00 edge-a Interface Gi0/1 down"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/device/syslog = %d: %s", rec.Code, rec.Body)
	}
	if got := countAction(t, "device.syslog_ingest"); got != 1 {
		t.Fatalf("AUD-08: device.syslog_ingest recorded %d times on the tenant chain, want exactly 1", got)
	}
	if acts := tenantActions(t); len(acts) != 1 || acts[0] != "device.syslog_ingest" {
		t.Fatalf("AUD-08: after syslog ingest the tenant chain holds %v, want exactly [device.syslog_ingest]", acts)
	}

	// 2. POST /v1/device/configs → exactly one device.config_archive event.
	rec = apiReq(t, h, http.MethodPost, "/v1/device/configs", tenant.ID,
		map[string]any{"device": "edge-a", "source": "startup-config", "content": "hostname edge-a\nenable secret raw-password\n"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/device/configs = %d: %s", rec.Code, rec.Body)
	}
	if got := countAction(t, "device.config_archive"); got != 1 {
		t.Fatalf("AUD-08: device.config_archive recorded %d times on the tenant chain, want exactly 1", got)
	}

	// The chain now holds exactly the two declared actions, in order — proving
	// each route emits precisely the action its policy declares and nothing else.
	acts := tenantActions(t)
	if len(acts) != 2 || acts[0] != "device.syslog_ingest" || acts[1] != "device.config_archive" {
		t.Fatalf("AUD-08: tenant audit chain = %v, want [device.syslog_ingest device.config_archive]", acts)
	}
}
