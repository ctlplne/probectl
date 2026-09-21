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
	"testing"

	"github.com/ctlplne/probectl/internal/branding"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestBrandingEndpointIsDeploymentScopedAndProbectlBranded(t *testing.T) {
	srv := testServer(fakePinger{})
	srv.cfg.ThemeOverrides = map[string]string{
		"--primary":            "28 85% 30%",
		"--primary-foreground": "0 0% 100%",
	}

	read := func(host, tenant string) (branding.Branding, http.Header) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/branding", nil)
		req.Host = host
		req = req.WithContext(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)))
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("branding %s: %d", host, rr.Code)
		}
		var got branding.Branding
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got, rr.Header()
	}

	a, headers := read("tenant-a.example", "tenant-a")
	b, _ := read("tenant-b.example", "tenant-b")
	if a.ProductName != "probectl" || b.ProductName != "probectl" {
		t.Fatalf("product identity changed: A=%+v B=%+v", a, b)
	}
	if a.TokenOverrides["--primary"] != "28 85% 30%" || b.TokenOverrides["--primary"] != "28 85% 30%" {
		t.Fatalf("deployment overrides differ by host: A=%+v B=%+v", a, b)
	}
	if vary := headers.Get("Vary"); vary != "" {
		t.Fatalf("deployment response must not vary by host: %q", vary)
	}
	if cache := headers.Get("Cache-Control"); cache != "public, max-age=60" {
		t.Fatalf("cache control = %q", cache)
	}
}
