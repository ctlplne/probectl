// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package auth

import (
	"bytes"
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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

// ResolveAndRotate resolves a cookie session and atomically rotates its opaque
// ID when the user's effective permission set changed since issuance. The
// replacement token is returned for the HTTP edge to set as a cookie before
// serving the request. Rotation covers both grants (privilege elevation) and
// revocations; the latter is intentionally just as strict.
func (a *Authenticator) ResolveAndRotate(r *http.Request) (*Principal, string, error) {
	token := TokenFromRequest(r)
	sess, err := a.mgr.Resolve(r.Context(), token)
	if err != nil {
		return nil, "", err
	}
	if sess == nil {
		return nil, "", nil
	}
	keys, err := a.perms.ForUser(r.Context(), sess.TenantID, sess.UserID)
	if err != nil {
		return nil, "", err
	}
	fingerprint := PermissionFingerprint(keys)
	if bytes.Equal(sess.AuthorizationHash, fingerprint) {
		return principalFromSession(sess, keys), "", nil
	}
	sess.AuthorizationHash = fingerprint
	replacement, err := a.mgr.Rotate(r.Context(), token, *sess)
	if err != nil {
		return nil, "", err
	}
	return principalFromSession(sess, keys), replacement, nil
}

// PermissionFingerprint returns a deterministic, non-secret digest of the
// effective permission keys. Sorting means a database query-plan order change
// does not spuriously rotate every session.
func PermissionFingerprint(keys []string) []byte {
	canonical := append([]string(nil), keys...)
	sort.Strings(canonical)
	return crypto.Hash([]byte(strings.Join(canonical, "\x00")))
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
