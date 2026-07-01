// SPDX-License-Identifier: LicenseRef-probectl-TBD

package auth

import (
	"context"
	"net/http"
)

type ctxKey int

const principalKey ctxKey = iota

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFrom returns the request's principal, or nil if unauthenticated.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey).(*Principal)
	return p
}

// Authenticator resolves a request's Principal from its session cookie, loading
// the user's effective permissions within its tenant. It does not enforce — the
// caller decides per route (tenant boundary first, then RBAC).
type Authenticator struct {
	mgr   *Manager
	perms PermissionLoader
}

// NewAuthenticator builds an authenticator.
func NewAuthenticator(mgr *Manager, perms PermissionLoader) *Authenticator {
	return &Authenticator{mgr: mgr, perms: perms}
}

// Resolve returns the principal for a request, or (nil, nil) when there is no
// valid session.
func (a *Authenticator) Resolve(r *http.Request) (*Principal, error) {
	sess, err := a.mgr.Resolve(r.Context(), TokenFromRequest(r))
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, nil
	}
	keys, err := a.perms.ForUser(r.Context(), sess.TenantID, sess.UserID)
	if err != nil {
		return nil, err
	}
	return principalFromSession(sess, keys), nil
}

// principalFromSession builds a Principal from a session + its permission keys.
func principalFromSession(sess *Session, keys []string) *Principal {
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	return &Principal{
		TenantID:       sess.TenantID,
		UserID:         sess.UserID,
		Email:          sess.Email,
		DisplayName:    sess.DisplayName,
		MFASatisfied:   sess.MFASatisfied,
		TimeZone:       sess.TimeZone,
		Locale:         sess.Locale,
		TenantTimeZone: sess.TenantTimeZone,
		TenantLocale:   sess.TenantLocale,
		Permissions:    set,
	}
}
