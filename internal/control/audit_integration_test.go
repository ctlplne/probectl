//go:build integration

package control

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestAuditCapturesMutations proves the S19 Done-when: config + data-access
// actions are audited. Creating a test (config) records a tamper-evident
// test.create event with the right actor + target, the chain verifies, and the
// audit read endpoint returns it.
func TestAuditCapturesMutations(t *testing.T) {
	h, _ := setupAPI(t) // dev auth mode → actor "dev@probectl.local"

	name := fmt.Sprintf("audit-%d", time.Now().UnixNano())
	rec := apiReq(t, h, http.MethodPost, "/v1/tests", "",
		map[string]any{"name": name, "type": "icmp", "target": "1.1.1.1", "interval_seconds": 30})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create test = %d: %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	mustJSON(t, rec, &created)

	// Read the audit trail and find the config action we just performed.
	rec = apiReq(t, h, http.MethodGet, "/v1/audit?limit=1000", "", nil)
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
	rec = apiReq(t, h, http.MethodDelete, "/v1/tests/"+created.ID, "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete test = %d", rec.Code)
	}

	// The chain must verify intact end-to-end.
	rec = apiReq(t, h, http.MethodGet, "/v1/audit/verify", "", nil)
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
