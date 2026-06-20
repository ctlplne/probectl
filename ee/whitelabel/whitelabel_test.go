// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package whitelabel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/branding"
)

func seeded(t *testing.T) (*MemStore, *Resolver) {
	t.Helper()
	store := NewMemStore()
	ctx := context.Background()
	if err := store.SetProviderBrand(ctx, Record{
		ProductName: "MSP NetWatch", EmailFooter: "© MSP GmbH",
		TokenOverrides: map[string]string{
			"--color-accent":          "#684af0",
			"--color-accent-hover":    "#7054f6",
			"--color-accent-strong":   "#684af0",
			"--color-accent-contrast": "#ffffff",
			"--color-focus":           "#684af0",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTenantBrand(ctx, Record{
		TenantID: "tnA", ProductName: "AcmeWatch", CustomDomain: "status.acme.example",
		LoginMessage: "Welcome to AcmeWatch",
		TokenOverrides: map[string]string{
			"--color-accent":          "#6a4cf0",
			"--color-accent-hover":    "#7054f6",
			"--color-accent-strong":   "#684af0",
			"--color-accent-contrast": "#ffffff",
		},
	}); err != nil {
		t.Fatal(err)
	}
	return store, NewResolver(store, time.Minute)
}

// TestBrandingApplication is the named test: tenant A sees A's brand, tenant
// B (no row) sees the provider master, an unknown deployment-default request
// sees the master too — and field precedence folds tenant → master → default.
func TestBrandingApplication(t *testing.T) {
	_, r := seeded(t)
	ctx := context.Background()

	a := r.For(ctx, "", "tnA")
	if a.ProductName != "AcmeWatch" || a.LoginMessage != "Welcome to AcmeWatch" {
		t.Fatalf("tenant A brand: %+v", a)
	}
	// Tenant override wins for accent; master fills the focus color it didn't set.
	if a.TokenOverrides["--color-accent"] != "#6a4cf0" || a.TokenOverrides["--color-focus"] != "#684af0" {
		t.Fatalf("token precedence: %+v", a.TokenOverrides)
	}
	if a.EmailFooter != "© MSP GmbH" { // master fills unset fields
		t.Fatalf("master fill: %+v", a)
	}

	b := r.For(ctx, "", "tnB")
	if b.ProductName != "MSP NetWatch" || b.TokenOverrides["--color-accent"] != "#684af0" {
		t.Fatalf("tenant B must get the provider master: %+v", b)
	}
}

// TestNoBleedRegression is THE S-T4 regression: resolving A then B then A
// (cache hot) never leaks A's brand into B — keys are strictly per tenant.
func TestNoBleedRegression(t *testing.T) {
	store, r := seeded(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ { // hot-cache loop
		a := r.For(ctx, "", "tnA")
		b := r.For(ctx, "", "tnB")
		if a.ProductName == b.ProductName {
			t.Fatalf("bleed: A=%q B=%q", a.ProductName, b.ProductName)
		}
		if b.TokenOverrides["--color-accent"] == "#6a4cf0" {
			t.Fatalf("tenant A's token bled into B: %+v", b.TokenOverrides)
		}
		if b.LoginMessage != "" {
			t.Fatalf("tenant A's login message bled into B: %+v", b)
		}
	}

	// A store failure degrades to the DEFAULT brand — never another tenant's.
	store.FailAll(true)
	fresh := NewResolver(store, time.Minute)
	d := fresh.For(ctx, "", "tnB")
	if d.ProductName != "probectl" {
		t.Fatalf("failure must degrade to the default brand: %+v", d)
	}
	store.FailAll(false)

	// Host resolution is exact: a *different* host gets no tenant mapping.
	if got := r.TenantForHost(ctx, "status.other.example"); got != "" {
		t.Fatalf("host bleed: %q", got)
	}
}

// TestCustomDomainRouting is the named test: the custom domain resolves the
// brand AND the login tenant; unknown hosts fall through; normalization
// strips ports/case.
func TestCustomDomainRouting(t *testing.T) {
	_, r := seeded(t)
	ctx := context.Background()

	b := r.For(ctx, "status.acme.example", "")
	if b.ProductName != "AcmeWatch" {
		t.Fatalf("domain brand: %+v", b)
	}
	if got := r.TenantForHost(ctx, "status.acme.example"); got != "tnA" {
		t.Fatalf("domain tenant: %q", got)
	}
	if got := r.TenantForHost(ctx, branding.NormalizeHost("Status.ACME.example:443")); got != "tnA" {
		t.Fatalf("normalized domain tenant: %q", got)
	}
	if got := r.TenantForHost(ctx, "unknown.example"); got != "" {
		t.Fatalf("unknown host must not map: %q", got)
	}
	// The explicit tenant beats the host (a signed-in user on a shared host).
	if b := r.For(ctx, "status.acme.example", "tnB"); b.ProductName != "MSP NetWatch" {
		t.Fatalf("tenant beats host: %+v", b)
	}

	// Moving the domain to a new value remaps atomically (after invalidate).
	store := NewMemStore()
	r2 := NewResolver(store, time.Minute)
	_ = store.SetTenantBrand(ctx, Record{TenantID: "tnC", ProductName: "C", CustomDomain: "c1.example"})
	if r2.TenantForHost(ctx, "c1.example") != "tnC" {
		t.Fatal("initial mapping")
	}
	_ = store.SetTenantBrand(ctx, Record{TenantID: "tnC", ProductName: "C", CustomDomain: "c2.example"})
	r2.Invalidate()
	if r2.TenantForHost(ctx, "c1.example") != "" || r2.TenantForHost(ctx, "c2.example") != "tnC" {
		t.Fatal("domain remap must drop the old host")
	}
}

// TestEmailTemplateBranding is the named test: the rendered email carries the
// tenant's brand (name/logo/footer), escapes hostile brand fields, and the
// From name falls back sensibly.
func TestEmailTemplateBranding(t *testing.T) {
	b := branding.Branding{
		ProductName: "AcmeWatch", LogoDataURI: "data:image/png;base64,iVBOR",
		EmailFromName: "AcmeWatch Alerts", EmailFooter: "© Acme MSP — reply to support@acme.example",
	}
	html, from, err := RenderEmail(b, Email{Subject: "Incident opened", Preheader: "p95 breach", BodyHTML: "<p>Incident <strong>#42</strong></p>"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AcmeWatch", "data:image/png;base64,iVBOR", "© Acme MSP", "<p>Incident <strong>#42</strong></p>", "Incident opened"} {
		if !strings.Contains(html, want) {
			t.Fatalf("email missing %q:\n%s", want, html)
		}
	}
	if from != "AcmeWatch Alerts" {
		t.Fatalf("from: %q", from)
	}

	// Hostile product names are escaped, never markup.
	hostile := branding.Branding{ProductName: `<script>alert(1)</script>`}
	html, from, err = RenderEmail(hostile, Email{Subject: "x", BodyHTML: "<p>ok</p>"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<script>") {
		t.Fatal("brand fields must be escaped")
	}
	if from != `<script>alert(1)</script>` { // a display NAME, escaped at the mail layer
		t.Fatalf("from fallback: %q", from)
	}

	// Empty brand falls back to the probectl default.
	html, from, err = RenderEmail(branding.Branding{}, Email{Subject: "x", BodyHTML: "<p>ok</p>"})
	if err != nil || !strings.Contains(html, "probectl") || from != "probectl" {
		t.Fatalf("default email brand: from=%q err=%v", from, err)
	}
}

func TestRecordValidate(t *testing.T) {
	good := Record{TenantID: "tnA", TokenOverrides: map[string]string{
		"--color-accent":          "#6a4cf0",
		"--color-accent-hover":    "#7054f6",
		"--color-accent-strong":   "#684af0",
		"--color-accent-contrast": "#ffffff",
	},
		LogoDataURI: "data:image/png;base64,AAAA", CustomDomain: "x.example"}
	if err := good.Validate(); err != nil {
		t.Fatalf("good record rejected: %v", err)
	}
	for _, bad := range []Record{
		{TokenOverrides: map[string]string{"--color-accent": "url(x)"}},
		{LogoDataURI: "https://cdn.example/logo.png"},
		{CustomDomain: "https://x.example"},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("bad record accepted: %+v", bad)
		}
	}
}
