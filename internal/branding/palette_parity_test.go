// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package branding

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The stylesheet is the single source of truth for the shipped palette. The
// control plane is a compiled binary and cannot read the web tree at runtime, so
// shippedContrastThemes duplicates those values — and this test is what keeps the
// duplicate honest. It exists because the design-language port renamed every
// token in the stylesheet and left this package validating operator overrides
// against a palette that no longer shipped: the names no longer matched, so every
// required pair was skipped and the WCAG check passed by doing nothing.
const tokensCSSPath = "../../web/src/styles/tokens.css"

var (
	tripletValueRe = regexp.MustCompile(`^-?[0-9.]+\s+-?[0-9.]+%\s+-?[0-9.]+%$`)
	declarationRe  = regexp.MustCompile(`(--[a-z0-9-]+)\s*:\s*([^;]+);`)
)

// cssThemeBlock returns the bare-triplet declarations of the block opened by the
// given selector text, which is how a theme is expressed in tokens.css.
func cssThemeBlock(t *testing.T, css, selector string) map[string]string {
	t.Helper()
	open := strings.Index(css, selector)
	if open < 0 {
		t.Fatalf("tokens.css does not contain the selector %q — the theme contract moved and this test must move with it", selector)
	}
	body := css[open+len(selector):]
	if end := strings.Index(body, "}"); end >= 0 {
		body = body[:end]
	}
	tokens := map[string]string{}
	for _, m := range declarationRe.FindAllStringSubmatch(body, -1) {
		if value := strings.TrimSpace(m[2]); tripletValueRe.MatchString(value) {
			tokens[m[1]] = value
		}
	}
	return tokens
}

func TestShippedPaletteMatchesTheStylesheetItValidates(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(tokensCSSPath)
	if err != nil {
		t.Fatalf("read %s: %v", tokensCSSPath, err)
	}
	css := string(raw)

	for _, tc := range []struct{ theme, selector string }{
		{"light", ":root {"},
		{"dark", "[data-theme='dark'] {"},
	} {
		shipped := cssThemeBlock(t, css, tc.selector)
		// A palette this small means the parser stopped matching the stylesheet,
		// which would make every comparison below trivially true.
		if len(shipped) < 40 {
			t.Fatalf("%s theme: parsed only %d color tokens from %s — the parser no longer understands the stylesheet, so this test proves nothing", tc.theme, len(shipped), tokensCSSPath)
		}
		got := shippedContrastThemes[tc.theme]
		if got == nil {
			t.Fatalf("shippedContrastThemes has no %q theme, but tokens.css ships one", tc.theme)
		}
		for name, want := range shipped {
			if have, ok := got[name]; !ok {
				t.Errorf("%s theme: tokens.css ships %s: %s, which this package does not know about — an operator override of it would be validated against nothing", tc.theme, name, want)
			} else if have != want {
				t.Errorf("%s theme: %s is %q in tokens.css but %q here — contrast is being validated against a color that does not ship", tc.theme, name, want, have)
			}
		}
		for name := range got {
			if _, ok := shipped[name]; !ok {
				t.Errorf("%s theme: this package validates %s, which tokens.css no longer defines — an override of it would be accepted and then have no effect", tc.theme, name)
			}
		}
	}
}

// TestEveryRequiredContrastPairResolves closes the hole that made the check
// vacuous: validateOverrideContrast skips a pair whose tokens are absent from the
// palette, so a renamed token silently removes a WCAG requirement instead of
// failing. Every pair must name tokens the palette actually defines.
func TestEveryRequiredContrastPairResolves(t *testing.T) {
	t.Parallel()
	if len(requiredContrastPairs) < 40 {
		t.Fatalf("only %d required contrast pairs — the pair set collapsed", len(requiredContrastPairs))
	}
	for theme, palette := range shippedContrastThemes {
		for _, pair := range requiredContrastPairs {
			for _, token := range []string{pair.fg, pair.bg, pair.backdrop} {
				if token == "" {
					continue
				}
				if _, ok := palette[token]; !ok {
					t.Errorf("%s theme: required pair %s on %s names %s, which the palette does not define — the pair is silently skipped and the requirement does not exist", theme, pair.fg, pair.bg, token)
				}
			}
		}
	}
}

// TestShippedThemesPassTheirOwnContrastRequirement is the baseline: with no
// overrides at all, both shipped themes must clear every pair. Without it the
// palette could ship a failing pair and only an operator override would reveal it.
func TestShippedThemesPassTheirOwnContrastRequirement(t *testing.T) {
	t.Parallel()
	if err := validateOverrideContrast(map[string]string{}); err != nil {
		t.Fatalf("a shipped theme fails its own WCAG requirement: %v", err)
	}
}

// TestOverridableTokensAreAllShipped keeps the operator-facing allowlist honest:
// every name it advertises must be a token the stylesheet defines, or the
// deployment config would accept a setting that changes nothing.
func TestOverridableTokensAreAllShipped(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(tokensCSSPath)
	if err != nil {
		t.Fatalf("read %s: %v", tokensCSSPath, err)
	}
	defined := map[string]bool{}
	for _, m := range declarationRe.FindAllStringSubmatch(string(raw), -1) {
		defined[m[1]] = true
	}
	var inert []string
	for _, name := range strings.Split(overridableTokens(), ", ") {
		if !defined[name] {
			inert = append(inert, name)
		}
	}
	sort.Strings(inert)
	if len(inert) > 0 {
		t.Errorf("these tokens are advertised as overridable but tokens.css does not define them, so setting them would do nothing: %s", strings.Join(inert, ", "))
	}
}
