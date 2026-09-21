// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package branding owns deployment-level product theming. The product name is
// always probectl; operators may override the allowlisted design tokens for an
// entire deployment, never per tenant or request host.
package branding

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Branding is the public /branding response. ProductName is fixed so an MSP
// deployment always presents the probectl banner. TokenOverrides apply to both
// shipped themes for every tenant in the deployment.
type Branding struct {
	ProductName    string            `json:"product_name"`
	TokenOverrides map[string]string `json:"token_overrides,omitempty"`
}

// Default is the unmodified probectl deployment theme.
func Default() Branding { return Branding{ProductName: "probectl"} }

// Deployment returns a defensive copy of the validated deployment overrides.
// Callers validate configuration at startup with ValidateOverrides.
func Deployment(overrides map[string]string) Branding {
	if len(overrides) == 0 {
		return Default()
	}
	cloned := make(map[string]string, len(overrides))
	for name, value := range overrides {
		cloned[name] = strings.TrimSpace(value)
	}
	return Branding{ProductName: "probectl", TokenOverrides: cloned}
}

// overridableNonColor lists the non-color tokens a deployment may set, with the
// value shape each one takes. Color tokens are deliberately absent: the shipped
// palette is their allowlist (isColorToken), so a renamed or newly shipped color
// token can never fall out of step with what the stylesheet actually defines.
// Spacing and typography scale remain structural product choices.
var overridableNonColor = map[string]string{
	"--radius-control": "radius",
	"--radius-panel":   "radius",
	"--radius-pill":    "radius",
	"--font-sans":      "font",
	"--font-mono":      "font",
	"--font-display":   "font",
}

// Value shapes are strict by construction: no url(), var(), semicolons, or
// expressions can make an operator override trigger a browser fetch/injection.
var (
	radiusRe = regexp.MustCompile(`^[0-9]{1,3}(px|rem|em|%)$`)
	fontRe   = regexp.MustCompile(`^[A-Za-z0-9 ,'"-]{1,120}$`)
)

// overridableTokens is the operator-facing list used in error messages.
func overridableTokens() string {
	names := make([]string, 0, len(overridableNonColor)+64)
	for name := range overridableNonColor {
		names = append(names, name)
	}
	for _, theme := range shippedContrastThemes {
		for name := range theme {
			names = append(names, name)
		}
		break // both themes define the same token names
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// MaxOverrides bounds the deployment override blob.
const MaxOverrides = 64

// ValidateOverrides rejects unknown token names, unsafe values, and sets that
// would make either shipped theme fail the WCAG text/UI contrast baseline.
func ValidateOverrides(overrides map[string]string) error {
	if len(overrides) > MaxOverrides {
		return fmt.Errorf("branding: too many token overrides (%d > %d)", len(overrides), MaxOverrides)
	}
	for name, value := range overrides {
		value = strings.TrimSpace(value)
		kind, isNonColor := overridableNonColor[name]
		switch {
		case isColorToken(name):
			// A color token must be the bare HSL triplet the stylesheet consumes
			// as hsl(var(--token) / <alpha-value>). A hex or rgb() value would
			// validate as a color and then make every rule using the token
			// unparseable, so it is refused with the shape spelled out rather
			// than accepted into a deployment that renders wrong.
			if !hslTripletRe.MatchString(value) {
				return fmt.Errorf("branding: %s must be a bare HSL triplet such as \"28 85%% 30%%\" (optionally \"28 85%% 30%% / 0.12\"); the stylesheet reads it as hsl(var(%s) / <alpha>), so %q would break every rule that uses it", name, name, value)
			}
		case isNonColor && kind == "radius":
			if !radiusRe.MatchString(value) {
				return fmt.Errorf("branding: unsafe or malformed value for %s", name)
			}
		case isNonColor:
			if !fontRe.MatchString(value) {
				return fmt.Errorf("branding: unsafe or malformed value for %s", name)
			}
		default:
			return fmt.Errorf("branding: token %q is not overridable (allowed: %s)", name, overridableTokens())
		}
	}
	return validateOverrideContrast(overrides)
}
