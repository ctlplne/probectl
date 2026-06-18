// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/httpbody"
	"github.com/imfeelingtheagi/probectl/internal/scim"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// auditSCIM records a SCIM provisioning action; the actor is the directory service.
func auditSCIM(ctx context.Context, sc tenancy.Scope, action, target string, data map[string]any) error {
	_, err := audit.TenantAppend(ctx, sc, "scim", action, target, data)
	return err
}

// isConflict reports whether a store error is a uniqueness/state conflict (→ SCIM 409).
func isConflict(err error) bool {
	var ae *apierror.Error
	return errors.As(err, &ae) && ae.Kind == apierror.KindConflict
}

// SCIM 2.0 endpoints (S31, F25). They are mounted OUTSIDE /v1 (an IdP provisioning
// surface, like the OTLP/change-ingest surfaces) and authenticate each request by
// a per-tenant SCIM bearer token — PRE-TENANT, like sessions/MCP. The token selects
// the tenant; all provisioning is then tenant-scoped (RLS). Deprovision (active=false
// or DELETE) revokes the user's sessions + tokens IMMEDIATELY (the S31 watch-out).
// Responses use the SCIM media type + the SCIM error envelope (IdPs are strict).

const scimMaxBody = 1 << 20

// scim wraps a SCIM handler with bearer→tenant resolution and SCIM-formatted
// errors, so the standard JSON error mapper never sees these routes.
func (s *Server) scim(fn func(w http.ResponseWriter, r *http.Request, tenantID string)) apiHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		tenantID, err := s.scimTenant(r)
		if err != nil {
			writeSCIMError(w, http.StatusUnauthorized, "", "invalid or missing bearer token")
			return nil
		}
		fn(w, r, tenantID)
		return nil
	}
}

// scimTenant resolves the SCIM bearer token to its tenant (pre-tenant auth).
func (s *Server) scimTenant(r *http.Request) (string, error) {
	if s.pool == nil {
		return "", store.ErrInvalidScimToken
	}
	tok := bearerToken(r)
	if tok == "" {
		return "", store.ErrInvalidScimToken
	}
	return store.NewScimTokens(s.pool).Authenticate(r.Context(), crypto.Hash([]byte(tok)))
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func scimBase(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/scim/v2"
}

// inTenantID runs fn within a tenant scope resolved from an explicit id (the SCIM
// token's tenant), not a request principal.
func (s *Server) inTenantID(ctx context.Context, tenantID string, fn func(context.Context, tenancy.Scope) error) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, fn)
}

// --- SCIM Users ---

func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	var in scim.User
	if !decodeSCIM(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.UserName) == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	var out *store.User
	err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		u, e := store.Users{}.CreateSCIM(ctx, sc, scimToUser(in))
		if e != nil {
			return e
		}
		out = u
		return auditSCIM(ctx, sc, "directory.provision", u.ID, map[string]any{"user_name": u.UserName})
	})
	if err != nil {
		s.writeSCIMStoreError(w, err, "user")
		return
	}
	writeSCIM(w, http.StatusCreated, userToSCIM(*out, scimBase(r)))
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request, tenantID string) {
	filter := scimEqFilter(r.URL.Query().Get("filter"), "userName")
	start := atoiDefault(r.URL.Query().Get("startIndex"), 1)
	count := atoiDefault(r.URL.Query().Get("count"), 100)
	base := scimBase(r)

	var resources []any
	err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		users, e := store.Users{}.List(ctx, sc, filter)
		if e != nil {
			return e
		}
		users = pageUsers(users, start, count)
		for _, u := range users {
			resources = append(resources, userToSCIM(u, base))
		}
		return nil
	})
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "list users failed")
		return
	}
	writeSCIM(w, http.StatusOK, scim.NewList(resources, len(resources), start, len(resources)))
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var u *store.User
	if err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Users{}.Get(ctx, sc, id)
		u = x
		return e
	}); err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, userToSCIM(*u, scimBase(r)))
}

func (s *Server) scimPutUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var in scim.User
	if !decodeSCIM(w, r, &in) {
		return
	}
	s.applyUserWrite(w, r, tenantID, id, func(_ *store.User) store.User {
		next := scimToUser(in)
		return next
	})
}

func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var patch scim.PatchOp
	if !decodeSCIM(w, r, &patch) {
		return
	}
	s.applyUserWrite(w, r, tenantID, id, func(cur *store.User) store.User {
		su := userToSCIM(*cur, scimBase(r))
		_ = scim.ApplyUserPatch(&su, patch.Operations)
		return scimToUser(su)
	})
}

// applyUserWrite loads the user, computes the next state via mutate, persists it,
// and — if the user is now inactive — revokes the user's sessions + tokens at once.
func (s *Server) applyUserWrite(w http.ResponseWriter, r *http.Request, tenantID, id string, mutate func(*store.User) store.User) {
	var out *store.User
	deactivated := false
	err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		cur, e := store.Users{}.Get(ctx, sc, id)
		if e != nil {
			return e
		}
		next := mutate(cur)
		u, e := store.Users{}.Update(ctx, sc, id, next)
		if e != nil {
			return e
		}
		out = u
		deactivated = u.Status != "active"
		action := "directory.update"
		if deactivated {
			action = "directory.deprovision"
		}
		return auditSCIM(ctx, sc, action, u.ID, map[string]any{"active": !deactivated})
	})
	if err != nil {
		s.writeSCIMStoreError(w, err, "user")
		return
	}
	if deactivated {
		s.revokeUserAccess(r.Context(), tenantID, out.ID)
	}
	writeSCIM(w, http.StatusOK, userToSCIM(*out, scimBase(r)))
}

func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	if err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, e := (store.Users{}).Get(ctx, sc, id); e != nil {
			return e
		}
		if e := (store.Users{}).Delete(ctx, sc, id); e != nil {
			return e
		}
		return auditSCIM(ctx, sc, "directory.deprovision", id, map[string]any{"deleted": true})
	}); err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "user not found")
		return
	}
	s.revokeUserAccess(r.Context(), tenantID, id)
	w.WriteHeader(http.StatusNoContent)
}

// revokeUserAccess is the immediate-revocation path: a deprovisioned user's
// sessions and bearer tokens are killed at once, so their next request fails.
func (s *Server) revokeUserAccess(ctx context.Context, tenantID, userID string) {
	if n, err := store.NewSessions(s.pool).DeleteAllForUser(ctx, tenantID, userID); err != nil {
		s.log.Warn("revoke sessions on deprovision failed", "error", err, "user", userID)
	} else if n > 0 {
		s.log.Info("revoked sessions on deprovision", "user", userID, "tenant_id", tenantID, "count", n)
	}
	if err := store.NewMCPTokens(s.pool).RevokeForUser(ctx, tenantID, userID); err != nil {
		s.log.Warn("revoke mcp tokens on deprovision failed", "error", err, "user", userID)
	}
}

// --- SCIM Groups (mapped to roles; members = role bindings) ---

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request, tenantID string) {
	var in scim.Group
	if !decodeSCIM(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.DisplayName) == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}
	var role *store.Role
	err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		role0, e := store.Roles{}.Create(ctx, sc, slugify(in.DisplayName), in.DisplayName, "SCIM group")
		if e != nil {
			return e
		}
		role = role0
		for _, m := range in.Members {
			if e := (store.RoleBindings{}).Bind(ctx, sc, "user", m.Value, role.ID); e != nil {
				return e
			}
		}
		return auditSCIM(ctx, sc, "directory.group_create", role.ID, map[string]any{"display": in.DisplayName})
	})
	if err != nil {
		s.writeSCIMStoreError(w, err, "group")
		return
	}
	writeSCIM(w, http.StatusCreated, s.groupToSCIM(r, tenantID, *role))
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request, tenantID string) {
	var resources []any
	err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		roles, e := store.Roles{}.List(ctx, sc)
		if e != nil {
			return e
		}
		for _, role := range roles {
			resources = append(resources, s.groupToSCIMScoped(ctx, sc, r, role))
		}
		return nil
	})
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", "list groups failed")
		return
	}
	writeSCIM(w, http.StatusOK, scim.NewList(resources, len(resources), 1, len(resources)))
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var g scim.Group
	if err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		role, e := store.Roles{}.Get(ctx, sc, id)
		if e != nil {
			return e
		}
		g = s.groupToSCIMScoped(ctx, sc, r, *role)
		return nil
	}); err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "group not found")
		return
	}
	writeSCIM(w, http.StatusOK, g)
}

func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	var patch scim.PatchOp
	if !decodeSCIM(w, r, &patch) {
		return
	}
	gp := scim.ParseGroupPatch(patch.Operations)
	if gp.DisplayName != nil && strings.TrimSpace(*gp.DisplayName) == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName must not be empty")
		return
	}
	var g scim.Group
	err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		role, e := store.Roles{}.Get(ctx, sc, id)
		if e != nil {
			return e
		}
		// The whole PATCH runs inside this one transaction, and every write
		// below propagates its error: the first failure returns, the
		// transaction rolls back EVERYTHING in the request, and the IdP gets
		// a real error to retry — never a 200 over a half-applied sync.
		if gp.DisplayName != nil {
			renamed, e := (store.Roles{}).Rename(ctx, sc, role.ID, strings.TrimSpace(*gp.DisplayName))
			if e != nil {
				return e
			}
			role = renamed
		}
		if gp.ReplaceAll != nil {
			cur, e := store.RoleBindings{}.MembersOfRole(ctx, sc, role.ID)
			if e != nil {
				return e
			}
			for _, m := range cur {
				if e := (store.RoleBindings{}).Unbind(ctx, sc, "user", m, role.ID); e != nil {
					return e
				}
			}
			for _, m := range *gp.ReplaceAll {
				if e := (store.RoleBindings{}).Bind(ctx, sc, "user", m, role.ID); e != nil {
					return e
				}
			}
		}
		for _, m := range gp.Add {
			if e := (store.RoleBindings{}).Bind(ctx, sc, "user", m, role.ID); e != nil {
				return e
			}
		}
		for _, m := range gp.Remove {
			if e := (store.RoleBindings{}).Unbind(ctx, sc, "user", m, role.ID); e != nil {
				return e
			}
		}
		g = s.groupToSCIMScoped(ctx, sc, r, *role)
		return auditSCIM(ctx, sc, "directory.group_update", role.ID, map[string]any{
			"added": len(gp.Add), "removed": len(gp.Remove), "renamed": gp.DisplayName != nil,
		})
	})
	if err != nil {
		var ae *apierror.Error
		if errors.As(err, &ae) && ae.Kind == apierror.KindNotFound {
			writeSCIMError(w, http.StatusNotFound, "", "group not found")
			return
		}
		// A failed sync must look failed: the transaction rolled back, so
		// nothing was applied — tell the IdP so it retries. Pre-fix, every
		// error here (including write failures) masqueraded as 404 after
		// silently keeping whatever half of the PATCH had "succeeded".
		writeSCIMError(w, http.StatusInternalServerError, "", "directory update failed; no changes were applied")
		return
	}
	writeSCIM(w, http.StatusOK, g)
}

func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request, tenantID string) {
	id := r.PathValue("id")
	if err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, e := (store.Roles{}).Get(ctx, sc, id); e != nil {
			return e
		}
		if e := (store.Roles{}).Delete(ctx, sc, id); e != nil {
			return e
		}
		return auditSCIM(ctx, sc, "directory.group_delete", id, nil)
	}); err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "group not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) groupToSCIM(r *http.Request, tenantID string, role store.Role) scim.Group {
	var g scim.Group
	if err := s.inTenantID(r.Context(), tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		g = s.groupToSCIMScoped(ctx, sc, r, role)
		return nil
	}); err != nil {
		// CODE-002: a scope-setup fault means group membership couldn't be
		// resolved — log it (the response would otherwise omit members silently).
		s.log.Warn("groupToSCIM: tenant scope failed", "tenant_id", tenantID, "role_id", role.ID, "error", err.Error())
	}
	return g
}

func (s *Server) groupToSCIMScoped(ctx context.Context, sc tenancy.Scope, r *http.Request, role store.Role) scim.Group {
	members, _ := store.RoleBindings{}.MembersOfRole(ctx, sc, role.ID)
	g := scim.Group{
		Schemas: []string{scim.SchemaGroup}, ID: role.ID, DisplayName: role.Name,
		Meta: &scim.Meta{ResourceType: "Group", Location: scimBase(r) + "/Groups/" + role.ID},
	}
	for _, m := range members {
		g.Members = append(g.Members, scim.Member{Value: m, Ref: scimBase(r) + "/Users/" + m})
	}
	return g
}

// --- discovery ---

func (s *Server) scimServiceProviderConfig(w http.ResponseWriter, _ *http.Request, _ string) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":               []string{scim.SchemaSPConfig},
		"documentationUri":      "https://docs.probectl.example/scim",
		"patch":                 map[string]any{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": 200},
		"changePassword":        map[string]any{"supported": false},
		"sort":                  map[string]any{"supported": false},
		"etag":                  map[string]any{"supported": false},
		"authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "description": "Per-tenant SCIM bearer token"}},
	})
}

// --- helpers: SCIM <-> store mapping + IO ---

func userToSCIM(u store.User, base string) scim.User {
	su := scim.User{
		Schemas: []string{scim.SchemaUser}, ID: u.ID, ExternalID: u.ExternalID,
		UserName: u.UserName, DisplayName: u.DisplayName, Active: u.Status == "active",
		Meta: &scim.Meta{ResourceType: "User", Created: ptr(u.CreatedAt), LastModified: ptr(u.UpdatedAt), Location: base + "/Users/" + u.ID},
	}
	if su.UserName == "" {
		su.UserName = u.Email
	}
	if u.Email != "" {
		su.Emails = []scim.Email{{Value: u.Email, Primary: true}}
	}
	if u.DisplayName != "" {
		su.Name = &scim.Name{Formatted: u.DisplayName}
	}
	if dept := u.Attributes["department"]; dept != "" {
		su.Enterprise = &scim.Enterprise{Department: dept}
	}
	return su
}

func scimToUser(su scim.User) store.User {
	u := store.User{
		ExternalID: su.ExternalID, UserName: su.UserName, DisplayName: su.DisplayName,
		Email: su.PrimaryEmail(), Status: statusFromActive(su.Active), Attributes: map[string]string{},
	}
	if u.Email == "" {
		u.Email = su.UserName // SCIM userName is frequently the email
	}
	if u.DisplayName == "" && su.Name != nil {
		u.DisplayName = su.Name.Formatted
	}
	if su.Enterprise != nil && su.Enterprise.Department != "" {
		u.Attributes["department"] = su.Enterprise.Department
	}
	return u
}

func statusFromActive(active bool) string {
	if active {
		return "active"
	}
	return "disabled"
}

func decodeSCIM(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpbody.DecodeJSON(r.Body, scimMaxBody, dst); err != nil {
		if errors.Is(err, httpbody.ErrTooLarge) {
			writeSCIMError(w, http.StatusRequestEntityTooLarge, "tooLarge", "SCIM body exceeds size cap")
			return false
		}
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "malformed SCIM body")
		return false
	}
	return true
}

func writeSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scim.ContentType)
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", scim.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(scim.NewError(status, scimType, detail))
}

// writeSCIMStoreError maps a store write error to a SCIM error (a uniqueness
// violation becomes 409). SEC-008: the response is GENERIC — internal store
// error text is logged server-side only, never echoed to the IdP client.
func (s *Server) writeSCIMStoreError(w http.ResponseWriter, err error, resource string) {
	if isConflict(err) {
		writeSCIMError(w, http.StatusConflict, "uniqueness", resource+" already exists")
		return
	}
	s.log.Warn("scim store error (returned generic)", "resource", resource, "error", err.Error())
	writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid "+resource+" attributes")
}

func scimEqFilter(filter, attr string) string {
	// minimal SCIM filter support: `<attr> eq "value"`
	f := strings.TrimSpace(filter)
	low := strings.ToLower(f)
	prefix := strings.ToLower(attr) + " eq "
	if !strings.HasPrefix(low, prefix) {
		return ""
	}
	return strings.Trim(strings.TrimSpace(f[len(prefix):]), `"`)
}

func pageUsers(u []store.User, start, count int) []store.User {
	if start < 1 {
		start = 1
	}
	i := start - 1
	if i >= len(u) {
		return nil
	}
	u = u[i:]
	if count >= 0 && count < len(u) {
		u = u[:count]
	}
	return u
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func slugify(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "group"
	}
	return out
}

func ptr[T any](v T) *T { return &v }
