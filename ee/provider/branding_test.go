// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/ee/whitelabel"
	"github.com/imfeelingtheagi/probectl/internal/branding"
	"github.com/imfeelingtheagi/probectl/internal/license"
)

// The S-T4 branding surface on the provider plane: tenant + master brand
// CRUD with validation, SoD, audit, read-only degrade, and the end-to-end
// resolution path through the CORE seam (the public /branding endpoint).

func brandedFixture(t *testing.T) (*fixture, *whitelabel.MemStore, *whitelabel.Resolver, string) {
	t.Helper()
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	store := whitelabel.NewMemStore()
	resolver := whitelabel.NewResolver(store, time.Minute)
	f.h.WithWhiteLabel(&WhiteLabel{Store: store, Invalidate: resolver.Invalidate})
	token := f.bootstrapAndLogin(t)
	return f, store, resolver, token
}

func TestBrandingCRUDAndAudit(t *testing.T) {
	f, _, resolver, admin := brandedFixture(t)

	// Default GET: an empty record (never an error).
	rec := f.doAuthed(t, admin, http.MethodGet, "/provider/v1/tenants/tnA/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("default get: %d", rec.Code)
	}

	// PUT a tenant brand; audited; resolvable through the CORE seam.
	body := map[string]any{
		"product_name":    "AcmeWatch",
		"login_message":   "Welcome",
		"custom_domain":   "status.acme.example",
		"token_overrides": map[string]string{"--color-accent": "#ff3300"},
	}
	rec = f.doAuthed(t, admin, http.MethodPut, "/provider/v1/tenants/tnA/branding", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("put branding: %d %s", rec.Code, rec.Body.String())
	}
	if f.audit.count("provider.branding_set") != 1 {
		t.Fatal("branding changes must be audited")
	}
	b := resolver.For(t.Context(), "", "tnA")
	if b.ProductName != "AcmeWatch" || b.TokenOverrides["--color-accent"] != "#ff3300" {
		t.Fatalf("resolution after PUT: %+v", b)
	}
	if got := resolver.TenantForHost(t.Context(), "status.acme.example"); got != "tnA" {
		t.Fatalf("domain mapping after PUT: %q", got)
	}

	// PUT the provider master; tenants without rows inherit it.
	rec = f.doAuthed(t, admin, http.MethodPut, "/provider/v1/branding",
		map[string]any{"product_name": "MSP NetWatch", "email_footer": "© MSP"})
	if rec.Code != http.StatusOK {
		t.Fatalf("put master: %d %s", rec.Code, rec.Body.String())
	}
	if b := resolver.For(t.Context(), "", "tnB"); b.ProductName != "MSP NetWatch" {
		t.Fatalf("master inheritance: %+v", b)
	}

	// Validation: hostile overrides/logos/domains are refused at the API.
	for _, bad := range []map[string]any{
		{"token_overrides": map[string]string{"--color-accent": "url(evil)"}},
		{"logo_data_uri": "https://cdn.example/logo.png"},
		{"custom_domain": "https://x.example"},
	} {
		if rec = f.doAuthed(t, admin, http.MethodPut, "/provider/v1/tenants/tnA/branding", bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad branding accepted (%v): %d", bad, rec.Code)
		}
	}
}

func TestBrandingSoDAndHidden(t *testing.T) {
	f, _, _, admin := brandedFixture(t)

	// A plain operator can READ but not WRITE brands (SoD).
	rec2 := f.doAuthed(t, admin, http.MethodPost, "/provider/v1/operators",
		map[string]string{"email": "op@msp.example", "name": "Op", "role": "operator"})
	var created struct {
		EnrollToken string `json:"enroll_token"`
	}
	mustDecode(t, rec2, &created)
	op := f.enrollAndLogin(t, created.EnrollToken, "op@msp.example", "operator-pw-123456")
	if rec := f.doAuthed(t, op, http.MethodGet, "/provider/v1/branding", nil); rec.Code != http.StatusOK {
		t.Fatalf("operator brand read: %d", rec.Code)
	}
	if rec := f.doAuthed(t, op, http.MethodPut, "/provider/v1/branding",
		map[string]any{"product_name": "X"}); rec.Code != http.StatusForbidden {
		t.Fatalf("SoD: operator set a brand: %d", rec.Code)
	}

	// Unattached = hidden.
	bare := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	tok := bare.bootstrapAndLogin(t)
	for _, probe := range []struct{ method, path string }{
		{http.MethodGet, "/provider/v1/branding"},
		{http.MethodPut, "/provider/v1/branding"},
		{http.MethodGet, "/provider/v1/tenants/tnA/branding"},
		{http.MethodPut, "/provider/v1/tenants/tnA/branding"},
	} {
		if rec := bare.doAuthed(t, tok, probe.method, probe.path, map[string]any{}); rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s must hide when unattached: %d", probe.method, probe.path, rec.Code)
		}
	}
}

func TestBrandingReadOnlyDegrade(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, -31*24*time.Hour)) // read_only
	store := whitelabel.NewMemStore()
	f.h.WithWhiteLabel(&WhiteLabel{Store: store})
	token := f.bootstrapAndLoginReadOnly(t)

	if rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/branding", nil); rec.Code != http.StatusOK {
		t.Fatalf("brand read in read-only: %d", rec.Code)
	}
	rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/branding", map[string]any{"product_name": "X"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "license_read_only") {
		t.Fatalf("brand write in read-only: %d %s", rec.Code, rec.Body.String())
	}
	// The ladder promise: EXISTING branding keeps rendering read-only — the
	// resolver still serves what was configured (branding persists).
	_ = store.SetTenantBrand(t.Context(), whitelabel.Record{TenantID: "tnA", ProductName: "AcmeWatch"})
	resolver := whitelabel.NewResolver(store, time.Minute)
	if b := resolver.For(t.Context(), "", "tnA"); b.ProductName != "AcmeWatch" {
		t.Fatalf("existing branding must persist in read-only: %+v", b)
	}
}

// TestCoreBrandingEndToEnd: the PUBLIC core endpoint + custom-domain login
// resolution, through the installed seam — and the default when uninstalled.
func TestCoreBrandingEndToEnd(t *testing.T) {
	store := whitelabel.NewMemStore()
	_ = store.SetTenantBrand(t.Context(), whitelabel.Record{
		TenantID: "tnA", ProductName: "AcmeWatch", CustomDomain: "status.acme.example",
		TokenOverrides: map[string]string{"--color-accent": "#ff3300"},
	})
	resolver := whitelabel.NewResolver(store, time.Minute)
	branding.SetSource(resolver)
	defer branding.SetSource(nil)

	// The seam answers by host (pre-auth) and by tenant.
	if b := branding.Resolve(t.Context(), "status.acme.example", ""); b.ProductName != "AcmeWatch" {
		t.Fatalf("host resolution: %+v", b)
	}
	if got := branding.TenantForHost(t.Context(), "status.acme.example"); got != "tnA" {
		t.Fatalf("login host mapping: %q", got)
	}
	// Another host stays default — A's brand never bleeds.
	if b := branding.Resolve(t.Context(), "other.example", ""); b.ProductName != "probectl" {
		t.Fatalf("default on unknown host: %+v", b)
	}

	branding.SetSource(nil)
	if b := branding.Resolve(t.Context(), "status.acme.example", "tnA"); b.ProductName != "probectl" {
		t.Fatalf("uninstalled seam must serve the default: %+v", b)
	}
}
