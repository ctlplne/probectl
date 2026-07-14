// SPDX-License-Identifier: LicenseRef-probectl-TBD

package branding

import (
	"math"
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
		{"--space-4": "40px"},
		{"--color-accent": "url(https://evil.example/x.png)"},
		{"--color-accent": "#fff; background: url(x)"},
		{"--color-accent": "var(--other)"},
		{"color-accent": "#fff"},
		{"--radius-md": "calc(1px + 1px)"},
		{"--font-sans": "Inter; }"},
		{"--color-bg": "expression(alert(1))"},
		{"--color-text": "#ffffff"},
		{"--color-accent": "#ff3300"},
		{"--color-chart-1": "#ffffff"},
	}
	for i, overrides := range bad {
		if err := ValidateOverrides(overrides); err == nil {
			t.Errorf("bad override set %d accepted: %v", i, overrides)
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

func TestDeploymentAlwaysUsesProbectlAndCopiesOverrides(t *testing.T) {
	overrides := map[string]string{"--radius-md": " 10px "}
	got := Deployment(overrides)
	if got.ProductName != "probectl" || got.TokenOverrides["--radius-md"] != "10px" {
		t.Fatalf("deployment branding = %+v", got)
	}
	overrides["--radius-md"] = "99px"
	if got.TokenOverrides["--radius-md"] != "10px" {
		t.Fatal("deployment response aliases mutable config")
	}
	if got := Default(); got.ProductName != "probectl" || len(got.TokenOverrides) != 0 {
		t.Fatalf("default branding = %+v", got)
	}
}

func TestParseContrastColorVariants(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want contrastColor
	}{
		{"short hex", "#abc", contrastColor{r: 0xaa / 255.0, g: 0xbb / 255.0, b: 0xcc / 255.0, a: 1}},
		{"short hex alpha", "#abcd", contrastColor{r: 0xaa / 255.0, g: 0xbb / 255.0, b: 0xcc / 255.0, a: 0xdd / 255.0}},
		{"long hex alpha", "#11223344", contrastColor{r: 0x11 / 255.0, g: 0x22 / 255.0, b: 0x33 / 255.0, a: 0x44 / 255.0}},
		{"rgb percentages", "rgb(100% 50% 0%)", contrastColor{r: 1, g: 0.5, b: 0, a: 1}},
		{"rgba slash alpha", "rgba(255 0 128 / 25%)", contrastColor{r: 1, g: 0, b: 128 / 255.0, a: 0.25}},
		{"negative hue wraps", "hsl(-120deg 100% 50% / 75%)", contrastColor{r: 0, g: 0, b: 1, a: 0.75}},
		{"comma hsla", "hsla(240, 100%, 50%, 0.5)", contrastColor{r: 0, g: 0, b: 1, a: 0.5}},
	}
	for _, c := range cases {
		got, err := parseContrastColor(c.in)
		if err != nil {
			t.Fatalf("%s: parse failed: %v", c.name, err)
		}
		assertContrastColor(t, c.name, got, c.want)
	}
}

func TestParseContrastColorRejectsInvalidInput(t *testing.T) {
	for _, in := range []string{
		"#12", "#zzzzzz", "rgb(1 2)", "rgb(300 0 0)", "rgba(0 0 0 2)",
		"hsl(0 101% 50%)", "hsl(nope 50% 50%)", "rgb(", "var(--color-text)",
	} {
		if _, err := parseContrastColor(in); err == nil {
			t.Fatalf("parseContrastColor(%q) succeeded, want error", in)
		}
	}
}

func assertContrastColor(t *testing.T, name string, got, want contrastColor) {
	t.Helper()
	const epsilon = 1e-9
	if math.Abs(got.r-want.r) > epsilon || math.Abs(got.g-want.g) > epsilon ||
		math.Abs(got.b-want.b) > epsilon || math.Abs(got.a-want.a) > epsilon {
		t.Fatalf("%s = %+v, want %+v", name, got, want)
	}
}
