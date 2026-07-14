// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/branding"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestBrandingEndpointIsDeploymentScopedAndProbectlBranded(t *testing.T) {
	srv := testServer(fakePinger{})
	srv.cfg.ThemeOverrides = map[string]string{
		"--color-accent":          "#6a4cf0",
		"--color-accent-hover":    "#7054f6",
		"--color-accent-strong":   "#684af0",
		"--color-accent-contrast": "#ffffff",
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
	if a.TokenOverrides["--color-accent"] != "#6a4cf0" || b.TokenOverrides["--color-accent"] != "#6a4cf0" {
		t.Fatalf("deployment overrides differ by host: A=%+v B=%+v", a, b)
	}
	if vary := headers.Get("Vary"); vary != "" {
		t.Fatalf("deployment response must not vary by host: %q", vary)
	}
	if cache := headers.Get("Cache-Control"); cache != "public, max-age=60" {
		t.Fatalf("cache control = %q", cache)
	}
}
