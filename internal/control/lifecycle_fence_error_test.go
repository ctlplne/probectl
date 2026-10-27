// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestLifecycleFenceRefusalIsTenantScoped(t *testing.T) {
	for _, message := range []string{"tenant audit writes are fenced for lifecycle erasure", "tenant writes are fenced for lifecycle erasure"} {
		t.Run(message, func(t *testing.T) {
			srv := testServer(nil)
			served := map[string]int{}
			srv.routeAudit = func(r *http.Request, _, _ string, _ map[string]any) error {
				if r.Header.Get("X-Probectl-Tenant") == "offboarding" {
					return fmt.Errorf("insert audit event: %w", &pgconn.PgError{Code: "55000", Message: message})
				}
				return nil
			}
			handler := srv.auditRoute(apiRoute{Method: http.MethodGet, Pattern: "/v1/tests"}, auditWrapped(auditFacetSensitiveRead), func(w http.ResponseWriter, r *http.Request) error {
				served[r.Header.Get("X-Probectl-Tenant")]++
				w.WriteHeader(http.StatusOK)
				return nil
			})
			for _, tenant := range []string{"offboarding", "active"} {
				req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
				req.Header.Set("X-Probectl-Tenant", tenant)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if tenant == "offboarding" {
					if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"tenant_offboarded"`) {
						t.Fatalf("lifecycle fence response = %d %s, want 403 tenant_offboarded", rec.Code, rec.Body.String())
					}
				} else if rec.Code != http.StatusOK {
					t.Fatalf("unrelated tenant = %d", rec.Code)
				}
			}
			if served["offboarding"] != 0 || served["active"] != 1 || srv.deferredAudit.pending() != 0 {
				t.Fatalf("served=%v deferred=%d; fenced reads must never serve or defer", served, srv.deferredAudit.pending())
			}
		})
	}
}

func TestUnrelatedObjectStateErrorRemainsInternal(t *testing.T) {
	for _, err := range []*pgconn.PgError{{Code: "55000", Message: "unrelated object state"}, {Code: "XX000", Message: "tenant audit writes are fenced for lifecycle erasure"}} {
		rec := httptest.NewRecorder()
		writeError(rec, httptest.NewRequest(http.MethodGet, "/v1/tests", nil), err)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("unrelated error = %d, want 500", rec.Code)
		}
	}
}
