// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package branding

import (
	"math"
	"strings"
	"testing"
)

func TestValidateOverrides(t *testing.T) {
	// A color override travels as the bare HSL triplet the stylesheet consumes,
	// and is validated against BOTH shipped themes — so a pair has to hold in
	// light and dark, which is why the action color ships with its own foreground.
	ok := map[string]string{
		"--primary":            "28 85% 30%",
		"--primary-foreground": "0 0% 100%",
		"--radius-panel":       "10px",
		"--font-sans":          "Sora, 'Helvetica Neue', sans-serif",
	}
	if err := ValidateOverrides(ok); err != nil {
		t.Fatalf("valid overrides rejected: %v", err)
	}
	bad := []map[string]string{
		{"--space-4": "40px"},                            // structural token, never overridable
		{"--primary": "url(https://evil.example/x.png)"}, // no browser fetch
		{"--primary": "28 85% 30%; background: url(x)"},  // no declaration escape
		{"--primary": "var(--other)"},                    // no indirection
		{"primary": "28 85% 30%"},                        // not a custom property
		{"--radius-panel": "calc(1px + 1px)"},
		{"--font-sans": "Sora; }"},
		{"--background": "expression(alert(1))"},
		// A hex value parses as a color but the stylesheet reads the token as
		// hsl(var(--primary) / <alpha>), so accepting it would render every rule
		// that uses the token unparseable.
		{"--primary": "#6a4cf0"},
		{"--primary": "rgb(106 76 240)"},
		// The retired vocabulary must be refused outright rather than accepted and
		// applied to nothing — the failure mode this whole file now guards.
		{"--color-accent": "28 85% 30%"},
		{"--color-text": "0 0% 100%"},
		// Contrast: white body text on warm paper, and a white series line on it.
		{"--foreground": "0 0% 100%"},
		{"--chart-1": "0 0% 100%"},
	}
	for i, overrides := range bad {
		if err := ValidateOverrides(overrides); err == nil {
			t.Errorf("bad override set %d accepted: %v", i, overrides)
		}
	}
	// The bound is checked before the allowlist, so synthetic names are fine here.
	big := map[string]string{}
	for i := 0; i <= MaxOverrides; i++ {
		big["--synthetic-"+strings.Repeat("a", i%5)+string(rune('a'+i%26))] = "0 0% 100%"
	}
	if len(big) > MaxOverrides {
		if err := ValidateOverrides(big); err == nil {
			t.Error("oversized override set accepted")
		}
	}
}

func TestDeploymentAlwaysUsesProbectlAndCopiesOverrides(t *testing.T) {
	overrides := map[string]string{"--radius-panel": " 10px "}
	got := Deployment(overrides)
	if got.ProductName != "probectl" || got.TokenOverrides["--radius-panel"] != "10px" {
		t.Fatalf("deployment branding = %+v", got)
	}
	overrides["--radius-panel"] = "99px"
	if got.TokenOverrides["--radius-panel"] != "10px" {
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
		// The shape every design token actually holds.
		{"bare triplet", "240 100% 50%", contrastColor{r: 0, g: 0, b: 1, a: 1}},
		{"bare triplet with alpha", "240 100% 50% / 0.5", contrastColor{r: 0, g: 0, b: 1, a: 0.5}},
		{"bare triplet with percent alpha", "240 100% 50% / 25%", contrastColor{r: 0, g: 0, b: 1, a: 0.25}},
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
		"hsl(0 101% 50%)", "hsl(nope 50% 50%)", "rgb(", "var(--foreground)",
		// Near-miss triplets: missing a unit, missing a component, out of range.
		"240 100 50", "240 100% ", "240 100% 50% / 2", "45 33% 95% 12%",
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
