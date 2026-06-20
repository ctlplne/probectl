// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/branding"
)

type hostBrandSource struct{ byHost map[string]branding.Branding }

func (s hostBrandSource) For(_ context.Context, host, _ string) branding.Branding {
	if b, ok := s.byHost[host]; ok {
		return b
	}
	return branding.Default()
}

func (s hostBrandSource) TenantForHost(_ context.Context, host string) string {
	if _, ok := s.byHost[host]; ok {
		return "11111111-1111-1111-1111-111111111111"
	}
	return ""
}

// The PUBLIC core branding endpoint (S-T4): pre-auth, Host-resolved, default
// probectl brand when no white-label source is installed (community), and
// host-keyed caching headers so a shared cache can never cross brands.
func TestBrandingEndpoint(t *testing.T) {
	srv := testServer(fakePinger{})

	// Community/unlicensed: the default brand, never an error.
	rec := do(srv, http.MethodGet, "/branding")
	if rec.Code != http.StatusOK {
		t.Fatalf("branding: %d", rec.Code)
	}
	var b branding.Branding
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.ProductName != "probectl" {
		t.Fatalf("default brand: %+v", b)
	}

	// Installed source: the brand follows the serving HOST (pre-auth).
	branding.SetSource(hostBrandSource{byHost: map[string]branding.Branding{
		"status.acme.example": {ProductName: "AcmeWatch", TokenOverrides: map[string]string{
			"--color-accent":          "#6a4cf0",
			"--color-accent-hover":    "#7054f6",
			"--color-accent-strong":   "#684af0",
			"--color-accent-contrast": "#ffffff",
		}},
	}})
	defer branding.SetSource(nil)

	req := httptest.NewRequest(http.MethodGet, "/branding", nil)
	req.Host = "status.acme.example:443"
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.ProductName != "AcmeWatch" || b.TokenOverrides["--color-accent"] != "#6a4cf0" {
		t.Fatalf("host brand: %+v", b)
	}
	if vary := rr.Header().Get("Vary"); vary != "Host" {
		t.Fatalf("brand responses must vary by Host: %q", vary)
	}

	// Another host: the default — A's brand never bleeds across hosts.
	req2 := httptest.NewRequest(http.MethodGet, "/branding", nil)
	req2.Host = "other.example"
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	_ = json.Unmarshal(rr2.Body.Bytes(), &b)
	if b.ProductName != "probectl" {
		t.Fatalf("cross-host bleed: %+v", b)
	}
}
