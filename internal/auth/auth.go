// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package auth is probectl's identity + access foundation (S18, F22): OIDC SSO,
// server-side sessions, and RBAC enforcement over the S2 role model.
//
// The two-level boundary (CLAUDE.md §7 guardrails 1, 5): a request resolves to
// exactly one tenant FIRST (the outermost security boundary), THEN RBAC decides
// whether the caller may perform the route's action within that tenant. A login
// resolves to a single tenant; provider operators are a separate privilege domain
// (S-T1) and do not authenticate into tenant data here.
package auth

import (
	"context"
	"time"
)

// Identity is the end-user identity an SSO provider returns after login.
type Identity struct {
	Subject     string
	Email       string
	DisplayName string
	TimeZone    string
	Locale      string
	// MFASatisfied is set from the ID token's amr/acr claims (SEC-005): true
	// when the IdP asserts a SECOND factor was used. It flows into the session
	// → principal → the "mfa" ABAC attribute, and gates PROBECTL_REQUIRE_MFA.
	MFASatisfied bool
	// Nonce is the ID token's nonce claim (SEC-004): the callback compares it
	// to the value minted at login — a mismatch/replayed token is refused.
	Nonce string
}

// Session is a server-side session. The opaque token is never stored — only its
// hash — so a database read cannot mint a session.
type Session struct {
	ID             string
	TenantID       string
	UserID         string
	Email          string
	DisplayName    string
	MFASatisfied   bool
	TimeZone       string
	Locale         string
	TenantTimeZone string
	TenantLocale   string
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

// Principal is the authenticated caller resolved for a request: its tenant, user,
// the effective permission set (RBAC), and the subject attributes that ABAC
// policies evaluate (e.g. department, mfa) — the two layers of the S31 model.
type Principal struct {
	TenantID       string
	UserID         string
	Email          string
	DisplayName    string
	MFASatisfied   bool
	TimeZone       string
	Locale         string
	TenantTimeZone string
	TenantLocale   string
	Permissions    map[string]bool
	// Attributes are the subject's ABAC attributes (from the user's SCIM-provisioned
	// attributes plus derived ones like "mfa"). nil when ABAC is not in use.
	Attributes map[string]string
}

// Has reports whether the principal holds permission key.
func (p *Principal) Has(key string) bool {
	return p != nil && p.Permissions[key]
}

// Attr returns a subject attribute value (empty if absent).
func (p *Principal) Attr(key string) string {
	if p == nil {
		return ""
	}
	return p.Attributes[key]
}

// SessionStore persists sessions, keyed by the hash of the opaque token.
// LookupByHash returns only non-expired sessions.
type SessionStore interface {
	Create(ctx context.Context, tokenHash []byte, s Session) error
	LookupByHash(ctx context.Context, tokenHash []byte) (*Session, error)
	DeleteByHash(ctx context.Context, tokenHash []byte) error
}

// PermissionLoader returns a user's effective permission keys within its tenant
// (resolved through the RBAC role bindings). The implementation enforces the
// tenant boundary (RLS) when reading.
type PermissionLoader interface {
	ForUser(ctx context.Context, tenantID, userID string) ([]string, error)
}

// Provider is one tenant's SSO provider (OIDC). AuthCodeURL begins the login;
// Exchange completes it, returning the verified end-user identity.
type Provider interface {
	AuthCodeURL(state, nonce string) string
	Exchange(ctx context.Context, code string) (*Identity, error)
}

// ProviderFactory resolves the SSO provider configured for a tenant — the
// per-tenant-IdP seam (a tenant brings its own SSO; a login resolves to exactly
// that tenant).
type ProviderFactory interface {
	For(ctx context.Context, tenantID string) (Provider, error)
}
