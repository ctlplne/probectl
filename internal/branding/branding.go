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

// tokenNameRe allowlists deployment-overridable color, radius, and font
// families. Spacing and typography scale remain structural product choices.
var tokenNameRe = regexp.MustCompile(`^--(color-[a-z0-9-]+|radius-(sm|md|lg)|font-sans|font-mono)$`)

// Value shapes are strict by construction: no url(), var(), semicolons, or
// expressions can make an operator override trigger a browser fetch/injection.
var (
	colorRe  = regexp.MustCompile(`^(#[0-9a-fA-F]{3,8}|rgba?\([0-9.,/% ]+\)|hsla?\([0-9.,/% deg]+\))$`)
	radiusRe = regexp.MustCompile(`^[0-9]{1,3}(px|rem|em|%)$`)
	fontRe   = regexp.MustCompile(`^[A-Za-z0-9 ,'"-]{1,120}$`)
)

// MaxOverrides bounds the deployment override blob.
const MaxOverrides = 64

// ValidateOverrides rejects unknown token names, unsafe values, and sets that
// would make either shipped theme fail the WCAG text/UI contrast baseline.
func ValidateOverrides(overrides map[string]string) error {
	if len(overrides) > MaxOverrides {
		return fmt.Errorf("branding: too many token overrides (%d > %d)", len(overrides), MaxOverrides)
	}
	for name, value := range overrides {
		if !tokenNameRe.MatchString(name) {
			return fmt.Errorf("branding: token %q is not overridable (allowed: --color-*, --radius-sm|md|lg, --font-sans, --font-mono)", name)
		}
		value = strings.TrimSpace(value)
		var ok bool
		switch {
		case strings.HasPrefix(name, "--color-"):
			ok = colorRe.MatchString(value)
		case strings.HasPrefix(name, "--radius-"):
			ok = radiusRe.MatchString(value)
		default:
			ok = fontRe.MatchString(value)
		}
		if !ok {
			return fmt.Errorf("branding: unsafe or malformed value for %s", name)
		}
	}
	return validateOverrideContrast(overrides)
}
