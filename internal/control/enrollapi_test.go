// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Sprint 11: with no enrollment service configured, the bootstrap surface
// answers 503 WITH the operator instruction — never a silent half-trust-root.
// (Token/replay/rotation behavior is covered by the enroll integration suite;
// this pins the unconfigured posture and the route mounting, DB-less.)
func TestEnrollRoutesUnconfiguredAnswer503(t *testing.T) {
	srv := testServer(nil) // no enroll service installed
	h := srv.Handler()

	for _, path := range []string{"/enroll/agent", "/enroll/agent/rotate"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s unconfigured = %d, want 503", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "agent-ca init") {
			t.Fatalf("%s must tell the operator HOW to configure: %s", path, rec.Body.String())
		}
	}

	// The admin mint route (the test harness runs dev-mode auth, so the
	// caller is authenticated and RBAC passes): unconfigured = the same 503 +
	// instruction. RBAC enforcement itself is covered by the shared
	// requirePermission suite over the route table.
	for _, path := range []string{"/v1/agents/enroll-tokens", "/v1/collectors/register"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "agent-ca init") {
			t.Fatalf("%s unconfigured = %d (%s), want 503 + init instruction", path, rec.Code, rec.Body.String())
		}
	}
}
