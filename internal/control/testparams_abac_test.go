// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

func TestGuardPrivilegedTestParamsEnforcesABAC(t *testing.T) {
	const (
		deniedTenant  = "11111111-1111-1111-1111-111111111111"
		allowedTenant = "22222222-2222-2222-2222-222222222222"
	)
	params := []struct {
		name       string
		param      string
		permission string
	}{
		{name: "private target override", param: "allow_private_targets", permission: permTestAllowPrivate},
	}
	handlers := []struct {
		name    string
		method  string
		path    string
		handler func(*Server) apiHandler
	}{
		{name: "create", method: http.MethodPost, path: "/v1/tests", handler: func(s *Server) apiHandler {
			return s.handleCreateTest
		}},
		{name: "update", method: http.MethodPut, path: "/v1/tests/test-id", handler: func(s *Server) apiHandler {
			return s.handleUpdateTest
		}},
	}

	for _, param := range params {
		t.Run(param.name, func(t *testing.T) {
			cache := newClosedABACCache(t)
			cache.data[deniedTenant] = abacEntry{
				expiry: time.Now().Add(time.Hour),
				policies: []auth.Policy{{
					ID:         "deny-" + param.param,
					Effect:     auth.PolicyDeny,
					Permission: param.permission,
					Resource:   map[string]string{auth.ResourceTenantKey: deniedTenant},
					Enabled:    true,
				}},
			}
			// A separate cache entry proves tenant A's deny cannot affect tenant B.
			cache.data[allowedTenant] = abacEntry{expiry: time.Now().Add(time.Hour)}
			s := &Server{abac: cache, pool: cache.pool}

			deniedReq := privilegedTestParamRequest(http.MethodPost, "/v1/tests", deniedTenant, param.permission, param.param)
			if err := s.guardAllowPrivate(deniedReq, map[string]string{param.param: "true"}); errKind(t, err) != apierror.KindForbidden {
				t.Fatalf("tenant-scoped ABAC deny = %v, want forbidden", err)
			}

			allowedReq := privilegedTestParamRequest(http.MethodPost, "/v1/tests", allowedTenant, param.permission, param.param)
			if err := s.guardAllowPrivate(allowedReq, map[string]string{param.param: "true"}); err != nil {
				t.Fatalf("tenant B inherited tenant A's ABAC deny: %v", err)
			}

			for _, endpoint := range handlers {
				t.Run(endpoint.name+" propagates deny", func(t *testing.T) {
					req := privilegedTestParamRequest(endpoint.method, endpoint.path, deniedTenant, param.permission, param.param)
					rec := httptest.NewRecorder()
					endpoint.handler(s).ServeHTTP(rec, req)
					if rec.Code != http.StatusForbidden {
						t.Fatalf("%s ABAC deny status = %d, want 403: %s", endpoint.name, rec.Code, rec.Body.String())
					}
				})
			}
		})
	}

	for _, tenantID := range []string{deniedTenant, allowedTenant} {
		t.Run("insecure TLS remains forbidden for tenant "+tenantID, func(t *testing.T) {
			cache := newClosedABACCache(t)
			cache.data[tenantID] = abacEntry{expiry: time.Now().Add(time.Hour)}
			s := &Server{abac: cache, pool: cache.pool}
			req := privilegedTestParamRequest(
				http.MethodPost,
				"/v1/tests",
				tenantID,
				permTestInsecureTLS,
				"insecure_skip_verify",
			)
			if err := s.guardAllowPrivate(req, map[string]string{"insecure_skip_verify": "true"}); errKind(t, err) != apierror.KindValidation {
				t.Fatalf("tenant %s insecure TLS override = %v, want validation rejection", tenantID, err)
			}
		})
	}

	for _, param := range params {
		t.Run(param.name+" policy load failure", func(t *testing.T) {
			for _, endpoint := range handlers {
				t.Run(endpoint.name+" fails closed", func(t *testing.T) {
					cache := newClosedABACCache(t)
					s := &Server{abac: cache, pool: cache.pool}
					req := privilegedTestParamRequest(endpoint.method, endpoint.path, deniedTenant, param.permission, param.param)
					rec := httptest.NewRecorder()
					endpoint.handler(s).ServeHTTP(rec, req)
					if rec.Code != http.StatusServiceUnavailable {
						t.Fatalf("%s policy-load failure status = %d, want 503: %s", endpoint.name, rec.Code, rec.Body.String())
					}
				})
			}
		})
	}
}

func privilegedTestParamRequest(method, path, tenantID, permission, param string) *http.Request {
	body := `{"name":"privileged override","type":"http","target":"https://example.test","params":{"` +
		param + `":"true"}}`
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	return req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{
		TenantID: tenantID,
		UserID:   "operator",
		Permissions: map[string]bool{
			permTestWrite: true,
			permission:    true,
		},
	}))
}
