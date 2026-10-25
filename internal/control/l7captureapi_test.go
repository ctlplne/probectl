// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type fakeL7PolicyStore struct {
	stmt          map[string]string
	writes        int
	auditProvided bool
}

func (f *fakeL7PolicyStore) TenantL7CaptureRedaction(_ context.Context, tenant string) (string, error) {
	return f.stmt[tenant], nil
}

func (f *fakeL7PolicyStore) SetTenantL7CaptureRedaction(_ context.Context, tenant, mode, _ string, auditTx func(context.Context, tenancy.Scope, string) error) error {
	if auditTx == nil {
		return govern.ErrAuditReceiptRequired
	}
	f.auditProvided = true
	f.writes++
	if f.stmt == nil {
		f.stmt = map[string]string{}
	}
	f.stmt[tenant] = mode
	return nil
}

func l7PolicyReq(t *testing.T, srv *Server, method, body string) (int, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, "/v1/ebpf/l7-capture-policy", nil)
	} else {
		req = httptest.NewRequest(method, "/v1/ebpf/l7-capture-policy", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Probectl-Tenant", tenancy.DefaultTenantID.String())
	srv.Handler().ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// D-64: the opt-in is core. With no license and no ee/ governance surface
// installed (testServer never calls WithGovernance), a tenant admin reads the
// metadata default and opts the tenant into headers, with the audit receipt.
func TestL7CapturePolicyIsCoreAndUnlicensed(t *testing.T) {
	fake := &fakeL7PolicyStore{}
	srv := testServer(nil)
	srv.l7policies = fake
	if code, out := l7PolicyReq(t, srv, http.MethodGet, ""); code != http.StatusOK || out["redaction"] != "metadata" || out["effective_floor"] != "metadata" {
		t.Fatalf("GET = %d %v, want the metadata default", code, out)
	}
	if code, out := l7PolicyReq(t, srv, http.MethodPut, `{"redaction":"headers"}`); code != http.StatusOK || out["effective_floor"] != "headers" {
		t.Fatalf("unlicensed headers opt-in = %d %v", code, out)
	}
	if fake.stmt[tenancy.DefaultTenantID.String()] != "headers" || !fake.auditProvided {
		t.Fatalf("opt-in not written with its audit receipt: %+v", fake)
	}
	// An update that omits the field never resets the opt-in (note N4).
	if code, _ := l7PolicyReq(t, srv, http.MethodPut, `{}`); code != http.StatusBadRequest && code != http.StatusUnprocessableEntity {
		t.Fatalf("omitted redaction = %d, want a validation error", code)
	}
	if code, _ := l7PolicyReq(t, srv, http.MethodPut, `{"redaction":"everything"}`); code != http.StatusBadRequest && code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown mode = %d", code)
	}
	if fake.writes != 1 || fake.stmt[tenancy.DefaultTenantID.String()] != "headers" {
		t.Fatalf("a refused update reached the store: %+v", fake)
	}
	// The ee/ governance surface stays hidden, and does not carry the field.
	if code, _ := l7PolicyReqPath(t, srv, "/v1/governance/policy"); code != http.StatusNotFound {
		t.Fatalf("governance surface unlicensed = %d, want 404", code)
	}
}

func l7PolicyReqPath(t *testing.T, srv *Server, path string) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Probectl-Tenant", tenancy.DefaultTenantID.String())
	srv.Handler().ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

// The regulated profile refuses headers and full, and shows the effective
// floor (never looser than metadata) even over an older stored statement.
func TestL7CapturePolicyRegulated(t *testing.T) {
	fake := &fakeL7PolicyStore{stmt: map[string]string{tenancy.DefaultTenantID.String(): "headers"}}
	srv := testServer(nil)
	srv.cfg.DeploymentProfile = "regulated"
	srv.l7policies = fake
	if code, out := l7PolicyReq(t, srv, http.MethodGet, ""); code != http.StatusOK || out["effective_floor"] != "metadata" {
		t.Fatalf("regulated GET = %d %v, want effective_floor metadata (note N5)", code, out)
	}
	for _, mode := range []string{"headers", "full"} {
		if code, _ := l7PolicyReq(t, srv, http.MethodPut, `{"redaction":"`+mode+`"}`); code != http.StatusBadRequest && code != http.StatusUnprocessableEntity {
			t.Fatalf("regulated %s = %d, want refused", mode, code)
		}
	}
	for _, mode := range []string{"metadata", "length"} {
		if code, _ := l7PolicyReq(t, srv, http.MethodPut, `{"redaction":"`+mode+`"}`); code != http.StatusOK {
			t.Fatalf("regulated %s = %d, want accepted", mode, code)
		}
	}
}
