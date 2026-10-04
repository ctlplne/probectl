// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/config"
)

// TestSensitiveResponsesAreNoStore proves WEB-16: authenticated API surfaces
// carry Cache-Control: no-store so tenant data is not cached by the browser or
// a shared proxy, while the cacheable UI bundle is left untouched.
func TestSensitiveResponsesAreNoStore(t *testing.T) {
	mw := securityHeaders(&config.Config{})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, p := range []string{"/v1/me", "/v1/audit", "/v1/incidents", "/auth/logout", "/scim/v2/Users", "/provider/tenants"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", p, got)
		}
	}

	// A static UI asset keeps its own cacheability (not forced no-store here).
	req := httptest.NewRequest(http.MethodGet, "/ui/assets/app-abc123.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Cache-Control"); got == "no-store" {
		t.Errorf("/ui asset must not be forced no-store, got %q", got)
	}
}
