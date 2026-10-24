// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func putGovernance(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v1/governance/policy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Probectl-Tenant", tenancy.DefaultTenantID.String())
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

// D-43: the tenant's L7 capture redaction floor is part of its governance
// policy. Unset reads as the metadata default; headers is an explicit opt-in
// written with the tenant audit receipt; an unknown value is refused.
func TestGovernanceL7CaptureRedactionOptIn(t *testing.T) {
	fake := &fakeGovStore{policies: map[string]govern.Policy{tenancy.DefaultTenantID.String(): {}}}
	srv := testServer(nil)
	srv.WithGovernance(fake)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/governance/policy", nil)
	req.Header.Set("X-Probectl-Tenant", tenancy.DefaultTenantID.String())
	srv.Handler().ServeHTTP(rr, req)
	var view map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view["l7_capture_redaction"] != "metadata" {
		t.Fatalf("unset floor reads %v, want the metadata default", view["l7_capture_redaction"])
	}

	if rr := putGovernance(t, srv, `{"l7_capture_redaction":"headers"}`); rr.Code != http.StatusOK {
		t.Fatalf("headers opt-in = %d %s", rr.Code, rr.Body)
	}
	if fake.lastSetPol.L7CaptureRedaction != "headers" || !fake.auditProvided {
		t.Fatalf("opt-in not written with an audit receipt: %+v audit=%v", fake.lastSetPol, fake.auditProvided)
	}
	if rr := putGovernance(t, srv, `{"l7_capture_redaction":"everything"}`); rr.Code != http.StatusBadRequest && rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown mode = %d, want a validation error", rr.Code)
	}
}

// Under the regulated profile the opt-ins are refused: the ingest strip enforces
// metadata for every tenant there.
func TestGovernanceL7CaptureRedactionRegulatedRefusesOptIns(t *testing.T) {
	fake := &fakeGovStore{policies: map[string]govern.Policy{}}
	srv := testServer(nil)
	srv.cfg.DeploymentProfile = "regulated"
	srv.WithGovernance(fake)
	for _, mode := range []string{"headers", "full"} {
		if rr := putGovernance(t, srv, `{"l7_capture_redaction":"`+mode+`"}`); rr.Code != http.StatusBadRequest && rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("regulated %s = %d %s, want refused", mode, rr.Code, rr.Body)
		}
	}
	if fake.setN != 0 {
		t.Fatalf("a refused opt-in reached the store (%d writes)", fake.setN)
	}
	for _, mode := range []string{"metadata", "length", ""} {
		if rr := putGovernance(t, srv, `{"l7_capture_redaction":"`+mode+`"}`); rr.Code != http.StatusOK {
			t.Fatalf("regulated %q = %d %s, want accepted", mode, rr.Code, rr.Body)
		}
	}
}

func TestEffectiveL7CaptureFloor(t *testing.T) {
	for _, tc := range []struct {
		stmt      string
		regulated bool
		want      string
	}{
		{"", false, "metadata"},
		{"headers", false, "headers"},
		{"full", false, "full"},
		{"length", false, "length"},
		{"bogus", false, "metadata"},
		{"headers", true, "metadata"},
		{"full", true, "metadata"},
		{"length", true, "length"},
	} {
		if got := govern.EffectiveL7CaptureFloor(tc.stmt, tc.regulated); got != tc.want {
			t.Errorf("EffectiveL7CaptureFloor(%q, %v) = %q, want %q", tc.stmt, tc.regulated, got, tc.want)
		}
	}
}
