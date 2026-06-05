// Package branding is the core white-label seam (S-T4, F54-full): the
// per-tenant brand model resolved at runtime onto the S8a design tokens.
//
// The TOKEN SYSTEM is core (S8a) and this seam is core so the tenant app can
// always ask "what brand am I?" — the answer is simply the probectl default
// until the ee/whitelabel resolver is installed at the main.go attach seam
// (white_label license feature). Hidden-unlicensed here means "the default
// brand", never an error: the login surface must render pre-auth either way.
package branding

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Branding is the per-tenant (or provider-master, or default) brand: the
// TenantBranding contract. TokenOverrides apply onto the S8a design tokens at
// runtime — branding is a token override, never a per-screen retrofit.
type Branding struct {
	// ProductName replaces the probectl wordmark (sidebar, titles, emails).
	ProductName string `json:"product_name"`
	// LogoDataURI is a small inline logo (data: image/svg+xml|png|jpeg).
	LogoDataURI string `json:"logo_data_uri,omitempty"`
	// LoginMessage renders on the branded login surface.
	LoginMessage string `json:"login_message,omitempty"`
	// TokenOverrides are S8a token-name → value pairs (validated: see
	// ValidateOverrides — allowlisted names, injection-safe values).
	TokenOverrides map[string]string `json:"token_overrides,omitempty"`
	// EmailFromName + EmailFooter brand notification emails.
	EmailFromName string `json:"email_from_name,omitempty"`
	EmailFooter   string `json:"email_footer,omitempty"`
}

// Default is the probectl brand (community deployments and any tenant with
// no override).
func Default() Branding {
	return Branding{ProductName: "probectl"}
}

// Source resolves brands. Implementations must be tenant-scoped: one
// tenant's brand may NEVER bleed into another's resolution (the S-T4
// regression). A resolution failure returns the safest answer — the default
// brand — not an error page (branding must never take a login down).
type Source interface {
	// For resolves the brand for a request: by tenant when known, else by
	// the serving host (custom-domain mapping), else the default.
	For(ctx context.Context, host, tenantID string) Branding
	// TenantForHost maps a custom domain to its tenant ("" = no mapping).
	TenantForHost(ctx context.Context, host string) string
}

type defaultSource struct{}

func (defaultSource) For(context.Context, string, string) Branding { return Default() }
func (defaultSource) TenantForHost(context.Context, string) string { return "" }

var (
	mu  sync.RWMutex
	src Source = defaultSource{}
)

// SetSource installs the white-label resolver (the ee attach seam). nil
// restores the default.
func SetSource(s Source) {
	mu.Lock()
	defer mu.Unlock()
	if s == nil {
		src = defaultSource{}
		return
	}
	src = s
}

// Resolve returns the brand for (host, tenant) via the installed source.
func Resolve(ctx context.Context, host, tenantID string) Branding {
	mu.RLock()
	s := src
	mu.RUnlock()
	return s.For(ctx, host, tenantID)
}

// TenantForHost resolves a custom domain to its tenant via the installed
// source ("" = no mapping; the caller falls back to its default).
func TenantForHost(ctx context.Context, host string) string {
	mu.RLock()
	s := src
	mu.RUnlock()
	return s.TenantForHost(ctx, host)
}

// --- The token-override contract (validated in CORE: the S8a token system
// owns which names exist and which value shapes are safe). ---

// tokenNameRe allowlists overridable token names: the S8a color/radius
// families. Spacing/type stay structural (white-label is brand, not layout).
var tokenNameRe = regexp.MustCompile(`^--(color-[a-z0-9-]+|radius-(sm|md|lg)|font-sans|font-mono)$`)

// Value shapes, strict by construction (no url(), no var(), no semicolons,
// no expressions — CSS-injection-safe):
var (
	colorRe  = regexp.MustCompile(`^(#[0-9a-fA-F]{3,8}|rgba?\([0-9.,/% ]+\)|hsla?\([0-9.,/% deg]+\))$`)
	radiusRe = regexp.MustCompile(`^[0-9]{1,3}(px|rem|em|%)$`)
	fontRe   = regexp.MustCompile(`^[A-Za-z0-9 ,'"-]{1,120}$`)
)

// MaxOverrides bounds an override set (defense against config-blob abuse).
const MaxOverrides = 64

// ValidateOverrides rejects unknown token names and unsafe values.
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
		default: // fonts
			ok = fontRe.MatchString(value)
		}
		if !ok {
			return fmt.Errorf("branding: unsafe or malformed value for %s", name)
		}
	}
	return nil
}

// logoRe constrains logos to small inline data URIs of safe image types.
var logoRe = regexp.MustCompile(`^data:image/(png|jpeg|svg\+xml);base64,[A-Za-z0-9+/=]+$`)

// MaxLogoBytes bounds the logo data URI (inline on every page load).
const MaxLogoBytes = 128 * 1024

// ValidateLogo rejects anything but a small inline image data URI.
func ValidateLogo(dataURI string) error {
	if dataURI == "" {
		return nil
	}
	if len(dataURI) > MaxLogoBytes {
		return fmt.Errorf("branding: logo exceeds %d bytes", MaxLogoBytes)
	}
	if !logoRe.MatchString(dataURI) {
		return fmt.Errorf("branding: logo must be a base64 data URI of type png, jpeg, or svg+xml")
	}
	return nil
}

// domainRe is a conservative hostname shape (no scheme, no port, no path).
var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

// ValidateDomain rejects malformed custom domains ("" = none).
func ValidateDomain(domain string) error {
	if domain == "" {
		return nil
	}
	if !domainRe.MatchString(domain) {
		return fmt.Errorf("branding: %q is not a valid hostname (lowercase, no scheme/port/path)", domain)
	}
	return nil
}

// NormalizeHost strips a port from a request Host header for mapping.
func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	return strings.TrimSuffix(host, ".")
}
