// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	LastActivityAt time.Time
	// AuthorizationHash fingerprints the effective permission grants (including
	// resource scope) at the moment this opaque token was issued. A changed
	// fingerprint causes an atomic token rotation before the request continues.
	AuthorizationHash []byte
}

// PermissionScope is the hierarchy level at which a role binding applies.
// Tenant is the compatibility/default scope: it authorizes the whole tenant.
// The other scopes authorize only the matching resource and its descendants.
type PermissionScope string

const (
	ScopeTenant       PermissionScope = "tenant"
	ScopeOrganization PermissionScope = "org"
	ScopeTeam         PermissionScope = "team"
	ScopeProject      PermissionScope = "project"
)

// PermissionGrant preserves the resource scope from the role binding that
// produced an effective permission. ScopeID is empty only for tenant scope.
type PermissionGrant struct {
	Permission string
	ScopeType  PermissionScope
	ScopeID    string
}

// ResourceLineage identifies a tenant-owned hierarchy resource after it has
// been resolved through the tenant's RLS-confined store.
type ResourceLineage struct {
	OrganizationID string
	TeamID         string
	ProjectID      string
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
	// Permissions contains tenant-wide grants only. It remains the compatibility
	// representation used by existing callers that construct a tenant principal.
	Permissions map[string]bool
	// PermissionGrants retains every valid tenant/resource-scoped RBAC grant.
	PermissionGrants []PermissionGrant
	// Attributes are the subject's ABAC attributes (from the user's SCIM-provisioned
	// attributes plus derived ones like "mfa"). nil when ABAC is not in use.
	Attributes map[string]string
}

// Has reports whether the principal holds permission key tenant-wide. A
// resource-scoped role binding must never make this method return true.
func (p *Principal) Has(key string) bool {
	if p == nil {
		return false
	}
	if p.Permissions[key] {
		return true
	}
	for _, grant := range p.PermissionGrants {
		if grant.Permission == key && validPermissionGrant(grant) && grant.ScopeType == ScopeTenant {
			return true
		}
	}
	return false
}

// HasAny reports whether the principal has any valid grant for key. Callers
// must still use HasAt before reading or mutating a concrete resource.
func (p *Principal) HasAny(key string) bool {
	if p == nil {
		return false
	}
	if p.Has(key) {
		return true
	}
	for _, grant := range p.PermissionGrants {
		if grant.Permission == key && validPermissionGrant(grant) {
			return true
		}
	}
	return false
}

// HasAt reports whether key applies to the already tenant-resolved lineage.
// Unknown/malformed scopes and incomplete target lineage fail closed.
func (p *Principal) HasAt(key string, lineage ResourceLineage) bool {
	if p == nil {
		return false
	}
	if p.Has(key) {
		return true
	}
	for _, grant := range p.PermissionGrants {
		if grant.Permission != key || !validPermissionGrant(grant) {
			continue
		}
		switch grant.ScopeType {
		case ScopeOrganization:
			if lineage.OrganizationID != "" && grant.ScopeID == lineage.OrganizationID {
				return true
			}
		case ScopeTeam:
			if lineage.TeamID != "" && grant.ScopeID == lineage.TeamID {
				return true
			}
		case ScopeProject:
			if lineage.ProjectID != "" && grant.ScopeID == lineage.ProjectID {
				return true
			}
		}
	}
	return false
}

func validPermissionGrant(grant PermissionGrant) bool {
	if grant.Permission == "" {
		return false
	}
	switch grant.ScopeType {
	case ScopeTenant:
		return grant.ScopeID == ""
	case ScopeOrganization, ScopeTeam, ScopeProject:
		return grant.ScopeID != ""
	default:
		return false
	}
}

// SessionStore persists sessions, keyed by the hash of the opaque token.
// LookupByHash returns only non-expired sessions.
type SessionStore interface {
	Create(ctx context.Context, tokenHash []byte, s Session) error
	LookupByHash(ctx context.Context, tokenHash []byte, idleTimeout time.Duration) (*Session, error)
	// RotateByHash atomically replaces oldHash with newHash and returns false
	// when oldHash no longer exists. The source row remains authoritative for
	// every field except activity and AuthorizationHash. Atomic replacement
	// prevents two concurrent requests from leaving two valid post-elevation
	// sessions behind.
	RotateByHash(ctx context.Context, oldHash, newHash []byte, s Session) (bool, error)
	// ReplaceAuthenticatedByHash is the login-only replacement seam. Unlike a
	// permission refresh, a completed IdP login makes s authoritative for
	// identity, MFA, preferences, and lifetime. The store atomically consumes
	// an existing current/legacy predecessor and creates at most one successor.
	// A false result means that predecessor was already consumed concurrently.
	ReplaceAuthenticatedByHash(ctx context.Context, oldHash, legacyOldHash, newHash []byte, s Session) (bool, error)
	DeleteByHash(ctx context.Context, tokenHash []byte) error
}

// PermissionLoader returns a user's effective permission grants within its
// tenant, preserving each role binding's resource scope. The implementation
// enforces the tenant boundary (RLS) when reading.
type PermissionLoader interface {
	ForUser(ctx context.Context, tenantID, userID string) ([]PermissionGrant, error)
}

// Provider is one tenant's SSO provider (OIDC). AuthCodeURL begins the login
// with the one-time PKCE verifier; Exchange must receive that same verifier to
// redeem the authorization code and return the verified end-user identity.
type Provider interface {
	AuthCodeURL(state, nonce, codeVerifier string) string
	Exchange(ctx context.Context, code, codeVerifier string) (*Identity, error)
}

// ProviderFactory resolves the SSO provider configured for a tenant — the
// per-tenant-IdP seam (a tenant brings its own SSO; a login resolves to exactly
// that tenant).
type ProviderFactory interface {
	For(ctx context.Context, tenantID string) (Provider, error)
}
