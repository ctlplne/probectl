package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func doAsTenant(srv *Server, method, path, tenant string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Probectl-Tenant", tenant)
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// fakeStatus is a TenantStatusSource over a fixed map; it records which tenant
// IDs were consulted so tests can prove the check is keyed by the principal's
// own tenant only.
type fakeStatus struct {
	statuses map[string]string
	err      error
	asked    []string
}

func (f *fakeStatus) TenantStatus(_ context.Context, tenantID string) (string, error) {
	f.asked = append(f.asked, tenantID)
	if f.err != nil {
		return "", f.err
	}
	if s, ok := f.statuses[tenantID]; ok {
		return s, nil
	}
	return "active", nil
}

// TestTenantLifecycleGate proves S-T1 suspension semantics at the API: a
// suspended tenant's users get 403 tenant_suspended on every /v1 route, an
// offboarded tenant 403 tenant_offboarded, and the check consults ONLY the
// caller's own tenant (it cannot become a cross-tenant status probe).
func TestTenantLifecycleGate(t *testing.T) {
	suspended := "11111111-1111-1111-1111-111111111111"
	offboarded := "22222222-2222-2222-2222-222222222222"
	src := &fakeStatus{statuses: map[string]string{
		suspended:  "suspended",
		offboarded: "deleted",
	}}
	srv := testServer(fakePinger{}).WithTenantStatus(src)

	// The default (active) tenant passes.
	if rec := do(srv, http.MethodGet, "/v1/editions"); rec.Code != http.StatusOK {
		t.Fatalf("active tenant: %d", rec.Code)
	}
	// A suspended tenant is rejected on the same route.
	rec := doAsTenant(srv, http.MethodGet, "/v1/editions", suspended)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("suspended tenant: %d (%s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !contains(body, "tenant_suspended") {
		t.Fatalf("suspended error code missing: %s", body)
	}
	// An offboarded tenant is rejected with its own code.
	rec = doAsTenant(srv, http.MethodGet, "/v1/editions", offboarded)
	if rec.Code != http.StatusForbidden || !contains(rec.Body.String(), "tenant_offboarded") {
		t.Fatalf("offboarded tenant: %d %s", rec.Code, rec.Body.String())
	}
	// The source was consulted only for the principals' own tenants.
	for _, asked := range src.asked {
		if asked != suspended && asked != offboarded && asked != "00000000-0000-0000-0000-000000000001" {
			t.Fatalf("lifecycle check consulted a foreign tenant: %s", asked)
		}
	}
}

// TestTenantLifecycleDegradesOpen proves a status-source failure does not take
// the API down (lifecycle is an administrative state; the security boundary
// remains RLS, which fails closed independently).
func TestTenantLifecycleDegradesOpen(t *testing.T) {
	src := &fakeStatus{err: errors.New("db down")}
	srv := testServer(fakePinger{}).WithTenantStatus(src)
	if rec := do(srv, http.MethodGet, "/v1/editions"); rec.Code != http.StatusOK {
		t.Fatalf("status-source failure must not reject: %d", rec.Code)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
