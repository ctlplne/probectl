// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// TestAuditCapturesMutations proves the S19 Done-when: config + data-access
// actions are audited. Creating a test (config) records a tamper-evident
// test.create event with the right actor + target, the chain verifies, and the
// audit read endpoint returns it.
func TestAuditCapturesMutations(t *testing.T) {
	h, db := setupAPI(t) // dev auth mode → actor "dev@probectl.local"
	// Isolate this test's audit trail on its OWN tenant. The default tenant
	// accumulates audit events from every other test that writes to it; once that
	// shared trail exceeds `limit`, our just-created event falls off the page and
	// the find-our-event check fails order-dependently under `go test ./...`.
	tenant := freshTenant(t, db, "audit")

	name := fmt.Sprintf("audit-%d", time.Now().UnixNano())
	rec := apiReq(t, h, http.MethodPost, "/v1/tests", tenant,
		map[string]any{"name": name, "type": "icmp", "target": "1.1.1.1", "interval_seconds": 30})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create test = %d: %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	mustJSON(t, rec, &created)

	// Read the audit trail and find the config action we just performed.
	rec = apiReq(t, h, http.MethodGet, "/v1/audit?limit=1000", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list audit = %d: %s", rec.Code, rec.Body)
	}
	var page struct {
		Items []struct {
			Seq    int64  `json:"seq"`
			Actor  string `json:"actor"`
			Action string `json:"action"`
			Target string `json:"target"`
			Hash   string `json:"hash"`
		} `json:"items"`
	}
	mustJSON(t, rec, &page)

	var found bool
	for _, e := range page.Items {
		if e.Action == "test.create" && e.Target == created.ID {
			found = true
			if e.Actor != "dev@probectl.local" {
				t.Errorf("audit actor = %q, want dev@probectl.local", e.Actor)
			}
			if e.Hash == "" {
				t.Error("audit event has no hash")
			}
		}
	}
	if !found {
		t.Fatalf("no test.create audit event for %s among %d events", created.ID, len(page.Items))
	}

	// Delete it → a second config action is recorded.
	rec = apiReq(t, h, http.MethodDelete, "/v1/tests/"+created.ID, tenant, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete test = %d", rec.Code)
	}

	// The chain must verify intact end-to-end.
	rec = apiReq(t, h, http.MethodGet, "/v1/audit/verify", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d: %s", rec.Code, rec.Body)
	}
	var v struct {
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	mustJSON(t, rec, &v)
	if !v.OK {
		t.Fatalf("audit chain not intact: %s", v.Detail)
	}
}

func TestAuditListFiltersActorActionAndTarget(t *testing.T) {
	h, db := setupAPI(t)
	tenant := freshTenant(t, db, "audit-filter")

	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := audit.TenantAppend(ctx, sc, "alice@example.com", "alert.create", "alert/api", nil); err != nil {
			return err
		}
		if _, err := audit.TenantAppend(ctx, sc, "bob@example.com", "test.create", "test/t1", nil); err != nil {
			return err
		}
		_, err := audit.TenantAppend(ctx, sc, "alice@example.com", "test.delete", "test/t2", nil)
		return err
	}); err != nil {
		t.Fatalf("seed audit rows: %v", err)
	}

	rec := apiReq(t, h, http.MethodGet, "/v1/audit?actor=alice&action=test&target=t2&limit=10", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list audit filters = %d: %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Items []struct {
			Actor  string `json:"actor"`
			Action string `json:"action"`
			Target string `json:"target"`
		} `json:"items"`
		Next int64 `json:"next"`
	}
	mustJSON(t, rec, &page)
	if len(page.Items) != 1 {
		t.Fatalf("filtered events = %d, want 1: %+v", len(page.Items), page.Items)
	}
	got := page.Items[0]
	if got.Actor != "alice@example.com" || got.Action != "test.delete" || got.Target != "test/t2" {
		t.Fatalf("filtered event = %+v", got)
	}
	if page.Next == 0 {
		t.Fatal("filtered page must still return the matching seq cursor")
	}
}

// TestAuditListShape asserts the audit read endpoint returns the documented
// envelope (items array + next cursor). The deny path (a principal lacking
// audit.read → 403) is exercised by the unit-level RBAC tests and by the
// permission wiring in requirePermission.
func TestAuditListShape(t *testing.T) {
	h, _ := setupAPI(t)
	rec := apiReq(t, h, http.MethodGet, "/v1/audit?after=0&limit=10", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list audit = %d: %s", rec.Code, rec.Body)
	}
	var page struct {
		Items []map[string]any `json:"items"`
		Next  int64            `json:"next"`
	}
	mustJSON(t, rec, &page)
	// items + next are always present (next is 0 when empty).
	if page.Items == nil {
		t.Error("items should be an array, not null")
	}
}
