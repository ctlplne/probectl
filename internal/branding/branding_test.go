// SPDX-License-Identifier: LicenseRef-probectl-TBD

package branding

import (
	"context"
	"strings"
	"testing"
)

func TestValidateOverrides(t *testing.T) {
	ok := map[string]string{
		"--color-accent":          "#6a4cf0",
		"--color-accent-hover":    "#7054f6",
		"--color-accent-strong":   "#684af0",
		"--color-accent-contrast": "#ffffff",
		"--color-warning":         "hsl(35deg 71% 42%)",
		"--radius-md":             "10px",
		"--font-sans":             "Inter, 'Helvetica Neue', sans-serif",
	}
	if err := ValidateOverrides(ok); err != nil {
		t.Fatalf("valid overrides rejected: %v", err)
	}
	bad := []map[string]string{
		{"--space-4": "40px"}, // layout tokens are not brand
		{"--color-accent": "url(https://evil.example/x.png)"}, // no urls
		{"--color-accent": "#fff; background: url(x)"},        // no injection
		{"--color-accent": "var(--other)"},                    // no var()
		{"color-accent": "#fff"},                              // must be a custom property
		{"--radius-md": "calc(1px + 1px)"},                    // no expressions
		{"--font-sans": "Inter; }"},                           // no structure chars
		{"--color-bg": "expression(alert(1))"},                // no expressions
		{"--color-text": "#ffffff"},                           // unreadable on light theme
		{"--color-accent": "#ff3300"},                         // inherited accent text fails contrast
		{"--color-chart-1": "#ffffff"},                        // chart/non-text indicator vanishes
	}
	for i, m := range bad {
		if err := ValidateOverrides(m); err == nil {
			t.Errorf("bad override set %d accepted: %v", i, m)
		}
	}
	big := map[string]string{}
	for i := 0; i <= MaxOverrides; i++ {
		big["--color-x"+strings.Repeat("a", i%5)+string(rune('a'+i%26))] = "#fff"
	}
	if len(big) > MaxOverrides {
		if err := ValidateOverrides(big); err == nil {
			t.Error("oversized override set accepted")
		}
	}
}

func TestValidateLogoAndDomain(t *testing.T) {
	if err := ValidateLogo("data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="); err != nil {
		t.Fatalf("valid logo rejected: %v", err)
	}
	if err := ValidateLogo(""); err != nil {
		t.Fatal("empty logo must be allowed")
	}
	for _, bad := range []string{
		"https://cdn.example/logo.png",                               // external fetch (sovereignty)
		"data:text/html;base64,PGI+",                                 // not an image
		"data:image/svg+xml;base64,<script>",                         // not base64
		"data:image/png;base64," + strings.Repeat("A", MaxLogoBytes), // too big
	} {
		if err := ValidateLogo(bad); err == nil {
			t.Errorf("bad logo accepted: %.40s", bad)
		}
	}

	if err := ValidateDomain("status.msp-customer.example"); err != nil {
		t.Fatalf("valid domain rejected: %v", err)
	}
	if err := ValidateDomain(""); err != nil {
		t.Fatal("empty domain must be allowed")
	}
	for _, bad := range []string{"https://x.example", "x.example/path", "UPPER.example", "localhost", "x..example", "-x.example"} {
		if err := ValidateDomain(bad); err == nil {
			t.Errorf("bad domain accepted: %q", bad)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"Status.Acme.Example:443": "status.acme.example",
		"status.acme.example.":    "status.acme.example",
		"status.acme.example":     "status.acme.example",
	} {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeSource struct{ byHost map[string]string }

func (f fakeSource) For(_ context.Context, host, tenantID string) Branding {
	if tenantID == "tnA" || f.byHost[host] == "tnA" {
		return Branding{ProductName: "AcmeWatch"}
	}
	return Default()
}

func (f fakeSource) TenantForHost(_ context.Context, host string) string { return f.byHost[host] }

func TestSeamDefaultAndInstall(t *testing.T) {
	SetSource(nil)
	if b := Resolve(context.Background(), "any.example", "tnA"); b.ProductName != "probectl" {
		t.Fatalf("default brand: %+v", b)
	}
	if tid := TenantForHost(context.Background(), "any.example"); tid != "" {
		t.Fatalf("default host mapping must be empty: %q", tid)
	}

	SetSource(fakeSource{byHost: map[string]string{"status.acme.example": "tnA"}})
	defer SetSource(nil)
	if b := Resolve(context.Background(), "", "tnA"); b.ProductName != "AcmeWatch" {
		t.Fatalf("installed source not used: %+v", b)
	}
	if tid := TenantForHost(context.Background(), "status.acme.example"); tid != "tnA" {
		t.Fatalf("host mapping: %q", tid)
	}
	// Another tenant on another host stays default — no bleed at the seam.
	if b := Resolve(context.Background(), "other.example", "tnB"); b.ProductName != "probectl" {
		t.Fatalf("bleed at the seam: %+v", b)
	}
}
