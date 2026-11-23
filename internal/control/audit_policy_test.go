// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/auth"
)

func TestAuditPolicyMatrixCoversRequiredRoutes(t *testing.T) {
	routes := testServer(nil).apiRoutes()
	seen := map[string]bool{}
	for _, rt := range routes {
		key := routeKey(rt.Method, rt.Pattern)
		seen[key] = true
		required, ok := auditRequiredFacet(rt.Method, rt.Pattern)
		if !ok {
			if p, found := auditPolicyFor(rt.Method, rt.Pattern); found && p.active() {
				t.Fatalf("%s has audit policy %+v but is classified as exempt", key, p)
			}
			continue
		}
		p, found := auditPolicyFor(rt.Method, rt.Pattern)
		if !found || !p.active() {
			t.Fatalf("%s requires a %s audit event but has no wrapper or explicit audit path", key, required)
		}
		if p.Facet != required {
			t.Fatalf("%s audit facet = %s, want %s", key, p.Facet, required)
		}
		if p.Action == "" || p.Target == "" {
			t.Fatalf("%s audit policy is missing action/target: %+v", key, p)
		}
	}
	for key := range auditPolicyMatrix {
		if !seen[key] {
			t.Fatalf("audit policy matrix references unregistered route %s", key)
		}
	}
}

func TestRTBHPreviewRequiresOperationalAudit(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	s := testServer(nil)
	calls := 0
	s.routeAudit = func(r *http.Request, action, target string, data map[string]any) error {
		calls++
		actor := auth.PrincipalFrom(r.Context())
		if actor == nil || actor.TenantID != tenant || action != "access.operate.remediation.rtbh_preview" ||
			target != "/v1/remediation/rtbh-preview" || data["facet"] != "operational_action" {
			t.Fatal("the preview lost its tenant or operational audit")
		}
		return &pgconn.PgError{Code: "25006"}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/remediation/rtbh-preview", nil)
	request.Header.Set("X-Probectl-Tenant", tenant)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if calls != 1 || response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") == "" || s.deferredAudit.pending() != 0 {
		t.Fatal("the preview proceeded without a durable operational audit", calls, response.Code)
	}
}

func TestSavedQueryReadRoutesRefuseUnauditedAccess(t *testing.T) {
	for _, resource := range []string{"query-source", "query-group?group=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "dependency-policy"} {
		for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
			t.Run(resource+"/"+tenant, func(t *testing.T) {
				s := testServer(nil)
				calls := 0
				s.routeAudit = func(r *http.Request, action, target string, data map[string]any) error {
					calls++
					actor := auth.PrincipalFrom(r.Context())
					if actor == nil || actor.TenantID != tenant || actor.UserID != "dev" || data["facet"] != "sensitive_read" || action == "" || target == "" {
						t.Fatal("query read audit lost the actual tenant, reader or facet")
					}
					return errors.New("audit store unavailable")
				}
				request := httptest.NewRequest(http.MethodGet, "/v1/alerts/rules/22222222-2222-4222-8222-222222222222/"+resource, nil)
				request.Header.Set("X-Probectl-Tenant", tenant)
				response := httptest.NewRecorder()
				s.Handler().ServeHTTP(response, request)
				if calls != 1 || response.Code != http.StatusInternalServerError || s.deferredAudit.pending() != 0 {
					t.Fatal("query data reached its handler without durable access audit", calls, response.Code)
				}
			})
		}
	}
}

func TestBGPASPathHistoryRefusesUnauditedAccess(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		t.Run(tenant, func(t *testing.T) {
			s := testServer(nil)
			calls := 0
			s.routeAudit = func(r *http.Request, action, target string, data map[string]any) error {
				calls++
				actor := auth.PrincipalFrom(r.Context())
				if actor == nil || actor.TenantID != tenant || actor.UserID != "dev" ||
					data["facet"] != "sensitive_read" || action == "" || target != "/v1/bgp/visibility/{id}/paths" {
					t.Fatal("AS path audit lost its tenant, reader, target or classification")
				}
				return errors.New("audit store unavailable")
			}
			request := httptest.NewRequest(http.MethodGet, "/v1/bgp/visibility/22222222-2222-4222-8222-222222222222/paths", nil)
			request.Header.Set("X-Probectl-Tenant", tenant)
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, request)
			if calls != 1 || response.Code != http.StatusInternalServerError || s.deferredAudit.pending() != 0 {
				t.Fatal("AS path read proceeded without its durable access audit", calls, response.Code)
			}
		})
	}
}

func TestPhysicalInventoryRefusesUnauditedAccess(t *testing.T) {
	const route = "/v1/device/physical-inventory"
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		t.Run(tenant, func(t *testing.T) {
			s := testServer(nil)
			calls := 0
			s.routeAudit = func(r *http.Request, action, target string, data map[string]any) error {
				calls++
				actor := auth.PrincipalFrom(r.Context())
				if actor == nil || actor.TenantID != tenant || action != "access.read.device.physical_inventory" ||
					target != route || data["facet"] != "sensitive_read" {
					t.Fatal("inventory access audit lost its tenant or sensitive-read classification")
				}
				return errors.New("audit store unavailable")
			}
			request := httptest.NewRequest(http.MethodGet, route, nil)
			request.Header.Set("X-Probectl-Tenant", tenant)
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, request)
			if calls != 1 || response.Code != http.StatusInternalServerError || s.deferredAudit.pending() != 0 {
				t.Fatal("inventory read proceeded without a durable access audit", calls, response.Code)
			}
		})
	}
}
