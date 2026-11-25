// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/ee/whitelabel"
	"github.com/ctlplne/probectl/internal/license"
)

func TestProviderBrandAPIRejectsAttributionControlsAndUnconditionalWrites(t *testing.T) {
	fixture := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	h := fixture.h.withCustomerBrands(whitelabel.NewStore(nil, nil, "https://console.example:8443/auth/callback"))
	admin := fixture.bootstrapAndLoginFast(t)
	operator, err := fixture.store.CreateOperator(t.Context(), Operator{
		Email: "operator@msp.example", Name: "Operator", Role: RoleOperator, Status: "disabled",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	member := fixture.activateAndIssue(t, operator)
	const path = "/provider/v1/tenants/00000000-0000-4000-8000-000000000021/brand"
	var spec struct {
		Paths map[string]map[string]struct {
			Responses map[string]json.RawMessage `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(providerSpec, &spec); err != nil {
		t.Fatal(err)
	}
	operations := spec.Paths["/provider/v1/tenants/{id}/brand"]
	documented := func(t *testing.T, method string, status int) {
		t.Helper()
		if _, ok := operations[strings.ToLower(method)].Responses[strconv.Itoa(status)]; !ok {
			t.Errorf("%s branding response %d is missing from OpenAPI", method, status)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		if rr := doReq(h, newReq(method, path, nil)); rr.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s returned %d", method, rr.Code)
		}
		documented(t, method, http.StatusUnauthorized)
		if rr := fixture.doAuthed(t, member, method, path, nil); rr.Code != http.StatusForbidden {
			t.Fatalf("non-admin %s returned %d", method, rr.Code)
		}
		documented(t, method, http.StatusForbidden)
	}
	t.Run("wrong media type", func(t *testing.T) {
		req := newReq(http.MethodPut, path, map[string]any{"name": "Northstar"})
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("If-Match", `"0"`)
		if rr := doReq(h, req); rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("form-safe brand write returned %d", rr.Code)
		}
		documented(t, http.MethodPut, http.StatusUnsupportedMediaType)
	})
	for _, tt := range []struct {
		name, match string
		body        map[string]any
		status      int
	}{
		{"missing revision", "", map[string]any{"name": "Northstar"}, 428},
		{"wildcard", "*", map[string]any{"name": "Northstar"}, http.StatusBadRequest},
		{"hide attribution", `"0"`, map[string]any{"name": "Northstar", "powered_by": false}, http.StatusBadRequest},
		{"replace link", `"0"`, map[string]any{"name": "Northstar", "powered_by_url": "https://other.example"}, http.StatusBadRequest},
		{"change badge color", `"0"`, map[string]any{"colors": map[string]string{"--powered-by-background": "0 0% 100%"}}, http.StatusBadRequest},
		{"claim shared console", `"0"`, map[string]any{"domain": "Console.Example."}, http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := newReq(http.MethodPut, path, tt.body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+admin)
			if tt.match != "" {
				req.Header.Set("If-Match", tt.match)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tt.status {
				t.Fatalf("brand write status = %d, expected %d", w.Code, tt.status)
			}
			documented(t, http.MethodPut, tt.status)
		})
	}
}
