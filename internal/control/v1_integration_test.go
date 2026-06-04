//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func setupAPI(t *testing.T) (http.Handler, *store.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, integrationDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		t.Skipf("no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		db.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(db.Close)
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "dev"}
	return New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil).Handler(), db
}

func apiReq(t *testing.T, h http.Handler, method, path, tenant string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tenant != "" {
		req.Header.Set("X-Probectl-Tenant", tenant)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func uuid(t *testing.T) string {
	t.Helper()
	b, err := crypto.Random(16)
	if err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func TestTestsCRUDAPI(t *testing.T) {
	h, _ := setupAPI(t)
	name := fmt.Sprintf("api-%d", time.Now().UnixNano())

	// Create → 201 + Location + body.
	rec := apiReq(t, h, http.MethodPost, "/v1/tests", "",
		map[string]any{"name": name, "type": "icmp", "target": "1.1.1.1", "interval_seconds": 30})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/v1/tests/") {
		t.Errorf("Location = %q", loc)
	}
	var created store.Test
	mustJSON(t, rec, &created)
	if created.ID == "" || created.Name != name || created.IntervalSeconds != 30 || !created.Enabled {
		t.Fatalf("created = %+v", created)
	}

	// List contains it.
	rec = apiReq(t, h, http.MethodGet, "/v1/tests", "", nil)
	var listed struct{ Items []store.Test }
	mustJSON(t, rec, &listed)
	if !containsID(listed.Items, created.ID) {
		t.Error("created test not present in list")
	}

	// Get → 200.
	if rec = apiReq(t, h, http.MethodGet, "/v1/tests/"+created.ID, "", nil); rec.Code != http.StatusOK {
		t.Errorf("get = %d", rec.Code)
	}

	// Update → 200 with changed fields.
	rec = apiReq(t, h, http.MethodPut, "/v1/tests/"+created.ID, "",
		map[string]any{"name": name, "type": "tcp", "target": "host:443", "interval_seconds": 120, "enabled": false})
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", rec.Code, rec.Body)
	}
	var updated store.Test
	mustJSON(t, rec, &updated)
	if updated.Type != "tcp" || updated.IntervalSeconds != 120 || updated.Enabled {
		t.Errorf("updated = %+v", updated)
	}

	// Duplicate name → 409.
	if rec = apiReq(t, h, http.MethodPost, "/v1/tests", "",
		map[string]any{"name": name, "type": "icmp", "target": "1.1.1.1"}); rec.Code != http.StatusConflict {
		t.Errorf("duplicate name = %d, want 409", rec.Code)
	}

	// Validation → 422.
	for _, bad := range []map[string]any{
		{"type": "icmp", "target": "x"},                                             // no name
		{"name": "n1", "type": "bogus", "target": "x"},                              // bad type
		{"name": "n2", "type": "icmp"},                                              // missing target
		{"name": "n3", "type": "icmp", "target": "x", "interval_seconds": 99999999}, // interval out of range
	} {
		if rec = apiReq(t, h, http.MethodPost, "/v1/tests", "", bad); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("invalid %v = %d, want 422", bad, rec.Code)
		}
	}

	// Malformed JSON → 400.
	req := httptest.NewRequest(http.MethodPost, "/v1/tests", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("malformed body = %d, want 400", rec2.Code)
	}

	// Bad tenant header → 400.
	if rec = apiReq(t, h, http.MethodGet, "/v1/tests", "not-a-uuid", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad tenant header = %d, want 400", rec.Code)
	}

	// Delete → 204, then 404.
	if rec = apiReq(t, h, http.MethodDelete, "/v1/tests/"+created.ID, "", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete = %d, want 204", rec.Code)
	}
	if rec = apiReq(t, h, http.MethodGet, "/v1/tests/"+created.ID, "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", rec.Code)
	}
}

// TestTestsAPITenantIsolation proves the /v1 API never crosses tenants: a test
// created in tenant B is invisible to the default tenant (RLS, end to end).
func TestTestsAPITenantIsolation(t *testing.T) {
	h, db := setupAPI(t)
	tn, err := store.NewTenants(db.Pool()).Create(context.Background(),
		fmt.Sprintf("apiiso-%d", time.Now().UnixNano()), "API Isolation")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	name := fmt.Sprintf("iso-%d", time.Now().UnixNano())

	rec := apiReq(t, h, http.MethodPost, "/v1/tests", tn.ID,
		map[string]any{"name": name, "type": "icmp", "target": "1.1.1.1"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create in tenant B = %d: %s", rec.Code, rec.Body)
	}
	var created store.Test
	mustJSON(t, rec, &created)

	// Default tenant must not see it in the list...
	rec = apiReq(t, h, http.MethodGet, "/v1/tests", "", nil)
	var listed struct{ Items []store.Test }
	mustJSON(t, rec, &listed)
	if containsID(listed.Items, created.ID) {
		t.Fatal("default tenant can see tenant B's test — isolation breach")
	}
	// ...nor fetch it by id (404, not 403 — it does not exist for this tenant).
	if rec = apiReq(t, h, http.MethodGet, "/v1/tests/"+created.ID, "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("cross-tenant get = %d, want 404", rec.Code)
	}
	// Tenant B can.
	if rec = apiReq(t, h, http.MethodGet, "/v1/tests/"+created.ID, tn.ID, nil); rec.Code != http.StatusOK {
		t.Errorf("tenant B get = %d, want 200", rec.Code)
	}
}

func TestAgentsAPI(t *testing.T) {
	h, db := setupAPI(t)
	agentID := uuid(t)
	err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.DefaultTenantID), db.Pool(),
		func(ctx context.Context, s tenancy.Scope) error {
			_, e := store.Agents{}.Register(ctx, s, agentID, "api-agent", "host-x", "0.1.0",
				"spiffe://probectl/tenant/x/agent/"+agentID, []string{"icmp"})
			return e
		})
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	if rec := apiReq(t, h, http.MethodGet, "/v1/agents", "", nil); rec.Code != http.StatusOK {
		t.Errorf("list agents = %d", rec.Code)
	}
	if rec := apiReq(t, h, http.MethodGet, "/v1/agents/"+agentID, "", nil); rec.Code != http.StatusOK {
		t.Errorf("get agent = %d", rec.Code)
	}

	rec := apiReq(t, h, http.MethodPatch, "/v1/agents/"+agentID, "", map[string]any{"name": "renamed"})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch agent = %d: %s", rec.Code, rec.Body)
	}
	var a store.Agent
	mustJSON(t, rec, &a)
	if a.Name != "renamed" {
		t.Errorf("rename failed: %+v", a)
	}

	if rec := apiReq(t, h, http.MethodDelete, "/v1/agents/"+agentID, "", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete agent = %d, want 204", rec.Code)
	}
	if rec := apiReq(t, h, http.MethodGet, "/v1/agents/"+agentID, "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", rec.Code)
	}
}

func mustJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rec.Body)
	}
}

func containsID(tests []store.Test, id string) bool {
	for _, x := range tests {
		if x.ID == id {
			return true
		}
	}
	return false
}
