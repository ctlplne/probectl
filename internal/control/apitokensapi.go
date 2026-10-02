// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// API/MCP bearer-token lifecycle (INV-03/RT-02). Tokens are created, listed and
// revoked through /v1/api-tokens (gated on security.keys — they are long-lived
// security credentials), carry a mandatory bounded expiry and an optional scope
// subset, and every create/revoke/first-use is written to the tenant audit
// chain. The token value is returned exactly once, at creation.

const (
	// apiTokenDefaultTTL is used when the request omits an explicit lifetime.
	apiTokenDefaultTTL = 90 * 24 * time.Hour
	// apiTokenMaxTTL bounds how long a token may live (max TTL policy, RT-02).
	apiTokenMaxTTL = 365 * 24 * time.Hour
	// scopeReadOnly restricts a token to read-only permissions.
	scopeReadOnly = "read"
)

// narrowPrincipalToScopes returns p restricted to the token's scope subset
// (INV-03/RT-02). Empty scopes leave the principal unchanged (full RBAC of the
// owner). "read" keeps only read permissions; any other scope entry is an
// explicit permission key that is kept when the owner holds it. The filter
// applies to BOTH the flat Permissions map and the resource-scoped
// PermissionGrants, because authorization (Principal.Has/HasAny/HasAt) consults
// both — so a read-only token truly cannot satisfy a write route's permission.
func narrowPrincipalToScopes(p *auth.Principal, scopes []string) *auth.Principal {
	if p == nil || len(scopes) == 0 {
		return p
	}
	readOnly := false
	explicit := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		switch strings.TrimSpace(s) {
		case "":
		case scopeReadOnly, "read-only", "readonly":
			readOnly = true
		default:
			explicit[strings.TrimSpace(s)] = true
		}
	}
	allow := func(key string) bool {
		if explicit[key] {
			return true
		}
		return readOnly && isReadPermission(key)
	}
	cp := *p
	np := make(map[string]bool, len(p.Permissions))
	for k, v := range p.Permissions {
		if v && allow(k) {
			np[k] = true
		}
	}
	cp.Permissions = np
	var grants []auth.PermissionGrant
	for _, g := range p.PermissionGrants {
		if allow(g.Permission) {
			grants = append(grants, g)
		}
	}
	cp.PermissionGrants = grants
	return &cp
}

// isReadPermission reports whether a permission key is read-only (its action
// segment is read/list/view). Any other action — write, investigate, approve,
// provision, erase, … — is treated as privileged and excluded from "read".
func isReadPermission(key string) bool {
	i := strings.LastIndex(key, ".")
	if i < 0 {
		return false
	}
	switch key[i+1:] {
	case "read", "list", "view":
		return true
	default:
		return false
	}
}

// normalizeScopes trims and drops empty scope entries.
func normalizeScopes(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

type createAPITokenRequest struct {
	Name           string   `json:"name"`
	ExpiresInHours int      `json:"expires_in_hours"`
	Scopes         []string `json:"scopes"`
}

// handleCreateAPIToken mints a token for the calling user, returns it once, and
// audits the creation. POST /v1/api-tokens.
func (s *Server) handleCreateAPIToken(w http.ResponseWriter, r *http.Request) error {
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	p := s.resolvePrincipal(r)
	if p == nil || p.UserID == "" {
		return apierror.Unauthorized("authentication required")
	}
	var req createAPITokenRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return apierror.BadRequest("name is required")
	}
	ttl := apiTokenDefaultTTL
	if req.ExpiresInHours > 0 {
		ttl = time.Duration(req.ExpiresInHours) * time.Hour
	}
	if ttl > apiTokenMaxTTL {
		return apierror.BadRequest("expires_in_hours exceeds the maximum token lifetime (8760 hours / 365 days)")
	}
	expiresAt := time.Now().Add(ttl).UTC()
	scopes := normalizeScopes(req.Scopes)

	token, err := auth.RandomToken()
	if err != nil {
		return err
	}
	id, err := store.NewMCPTokens(s.pool).CreateWithLifetime(r.Context(), tenantID, p.UserID, req.Name, crypto.Hash([]byte(token)), expiresAt, scopes)
	if err != nil {
		return err
	}
	if auditErr := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, "apitoken.create", id, map[string]any{"name": req.Name, "scopes": scopes, "expires_at": expiresAt})
	}); auditErr != nil {
		s.log.Warn("apitoken create audit failed", "tenant_id", tenantID, "token_id", id, "error", auditErr.Error())
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id,
		"name":       req.Name,
		"scopes":     scopes,
		"expires_at": expiresAt,
		"token":      token, // the secret, shown exactly once
	})
	return nil
}

// handleListAPITokens lists the tenant's tokens (metadata only, never the
// secret). GET /v1/api-tokens.
func (s *Server) handleListAPITokens(w http.ResponseWriter, r *http.Request) error {
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	tokens, err := store.NewMCPTokens(s.pool).List(r.Context(), tenantID)
	if err != nil {
		return err
	}
	if tokens == nil {
		tokens = []store.TokenInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tokens})
	return nil
}

// handleRevokeAPIToken revokes exactly one token by id, leaving the user's other
// tokens working, and audits it. DELETE /v1/api-tokens/{id}.
func (s *Server) handleRevokeAPIToken(w http.ResponseWriter, r *http.Request) error {
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		return apierror.BadRequest("token id is required")
	}
	found, err := store.NewMCPTokens(s.pool).RevokeByID(r.Context(), tenantID, id)
	if err != nil {
		return err
	}
	if !found {
		return apierror.NotFound("no live token with that id")
	}
	if auditErr := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, "apitoken.revoke", id, nil)
	}); auditErr != nil {
		s.log.Warn("apitoken revoke audit failed", "tenant_id", tenantID, "token_id", id, "error", auditErr.Error())
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "id": id})
	return nil
}
