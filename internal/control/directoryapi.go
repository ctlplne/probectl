// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-027: tenant-scoped people & roles. A role binding may come from SCIM
// group sync, from the control-host bootstrap-admin command, or — here — from
// a tenant administrator holding directory.write. RBAC is deny-by-default, so
// a user without a binding can see nothing; the last administrator of a tenant
// cannot be removed, and every mutation lands in the tenant audit stream.

const (
	directoryListMax   = 500
	directoryAdminRole = "admin"
)

type directoryUser struct {
	store.User
	Roles []string `json:"roles"`
	// ScopedRoles are roles bound at an org, team or project scope: delegated
	// administration of that branch, never a tenant-wide grant.
	ScopedRoles []store.ScopedRole `json:"scoped_roles"`
}

type directoryRole struct {
	store.Role
	Permissions []string `json:"permissions"`
	Members     int      `json:"members"`
}

// directoryFailure passes domain errors (not found, conflict, validation)
// through unchanged and wraps anything else as an internal failure.
func (s *Server) directoryFailure(tid, what string, err error) error {
	var ae *apierror.Error
	if errors.As(err, &ae) {
		return err
	}
	s.log.Warn("directory "+what+" failed", "tenant", tid, "error", err)
	return apierror.Internal("failed to " + what).Wrap(err)
}

func (s *Server) directoryUserWithRoles(ctx context.Context, sc tenancy.Scope, u *store.User) (directoryUser, error) {
	roles, err := (store.RoleBindings{}).RolesOfUser(ctx, sc, u.ID)
	if err != nil {
		return directoryUser{}, err
	}
	slugs := make([]string, 0, len(roles))
	for _, r := range roles {
		slugs = append(slugs, r.Slug)
	}
	scoped, err := (store.RoleBindings{}).ScopedRolesOfUser(ctx, sc, u.ID)
	if err != nil {
		return directoryUser{}, err
	}
	return directoryUser{User: *u, Roles: slugs, ScopedRoles: scoped}, nil
}

// directoryScope reads an optional org/team/project scope for a role grant. An
// empty or "tenant" type is the tenant-wide grant; anything else must name an
// existing org, team or project of the caller's tenant.
func directoryScope(scopeType, scopeID string) (string, string, error) {
	scopeType = strings.ToLower(strings.TrimSpace(scopeType))
	scopeID = strings.ToLower(strings.TrimSpace(scopeID))
	switch scopeType {
	case "", "tenant":
		if scopeID != "" {
			return "", "", apierror.Validation("scope_id is only valid with scope_type org, team or project")
		}
		return "", "", nil
	case "org", "team", "project":
		if !uuidRe.MatchString(scopeID) {
			return "", "", apierror.Validation("scope_id must be the id of an org, team or project")
		}
		return scopeType, scopeID, nil
	default:
		return "", "", apierror.Validation("scope_type must be tenant, org, team or project")
	}
}

// handleDirectoryUserList serves GET /v1/directory/users: every user of the
// caller's tenant with the role slugs bound at tenant scope.
func (s *Server) handleDirectoryUserList(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.pool == nil {
		return apierror.NotFound("not found")
	}
	var (
		out   = []directoryUser{}
		total int
	)
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		users, n, err := (store.Users{}).ListPage(ctx, sc, store.UserFilter{}, 1, directoryListMax)
		if err != nil {
			return err
		}
		byUser, err := (store.RoleBindings{}).RoleSlugsByUser(ctx, sc)
		if err != nil {
			return err
		}
		scopedByUser, err := (store.RoleBindings{}).ScopedRolesByUser(ctx, sc)
		if err != nil {
			return err
		}
		total = n
		for i := range users {
			slugs := byUser[users[i].ID]
			if slugs == nil {
				slugs = []string{}
			}
			scoped := scopedByUser[users[i].ID]
			if scoped == nil {
				scoped = []store.ScopedRole{}
			}
			out = append(out, directoryUser{User: users[i], Roles: slugs, ScopedRoles: scoped})
		}
		return nil
	}); err != nil {
		return s.directoryFailure(tid, "list users", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "total": total})
	return nil
}

// handleDirectoryRoleList serves GET /v1/directory/roles: the tenant's roles
// with their permissions and member counts.
func (s *Server) handleDirectoryRoleList(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.pool == nil {
		return apierror.NotFound("not found")
	}
	out := []directoryRole{}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		roles, _, err := (store.Roles{}).ListPage(ctx, sc, 1, directoryListMax)
		if err != nil {
			return err
		}
		for i := range roles {
			perms, err := (store.Roles{}).Permissions(ctx, sc, roles[i].ID)
			if err != nil {
				return err
			}
			members, err := (store.RoleBindings{}).MembersOfRole(ctx, sc, roles[i].ID)
			if err != nil {
				return err
			}
			if perms == nil {
				perms = []string{}
			}
			out = append(out, directoryRole{Role: roles[i], Permissions: perms, Members: len(members)})
		}
		return nil
	}); err != nil {
		return s.directoryFailure(tid, "list roles", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
	return nil
}

// restrictedDirectoryRole reports whether a role slug may not be bound through
// the tenant directory API (AUTHZ-09). ir-investigator is a separation-of-duty
// group populated only via SCIM; every directory bind path checks this so a new
// path cannot silently reintroduce the self-binding SoD bypass.
func restrictedDirectoryRole(slug string) bool {
	return slug == "ir-investigator"
}

// handleDirectoryUserCreate serves POST /v1/directory/users: create a person
// before their first SSO login (so a role can be waiting for them) and
// optionally bind one role in the same audited step.
func (s *Server) handleDirectoryUserCreate(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.pool == nil {
		return apierror.NotFound("not found")
	}
	var in struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" || !strings.Contains(email, "@") {
		return apierror.Validation("email is required and must be an address")
	}
	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		displayName = email
	}
	slug := strings.ToLower(strings.TrimSpace(in.Role))
	// AUTHZ-09: ir-investigator is a SCIM-only separation-of-duty group; the
	// directory API must not bind it on the create path either.
	if restrictedDirectoryRole(slug) {
		return apierror.Forbidden("the ir-investigator role is a separation-of-duty group and can only be assigned through SCIM")
	}

	var created directoryUser
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var role *store.Role
		if slug != "" {
			var err error
			role, err = (store.Roles{}).GetBySlug(ctx, sc, slug)
			if err != nil {
				return apierror.Validation("unknown role " + slug)
			}
		}
		u, err := (store.Users{}).Create(ctx, sc, email, displayName)
		if err != nil {
			return err
		}
		if role != nil {
			if err := (store.RoleBindings{}).Bind(ctx, sc, "user", u.ID, role.ID); err != nil {
				return err
			}
		}
		created, err = s.directoryUserWithRoles(ctx, sc, u)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "directory.user_create", tid, map[string]any{
			"user_id": u.ID, "email": email, "role": slug,
		})
	}); err != nil {
		return s.directoryFailure(tid, "create user", err)
	}
	writeJSON(w, http.StatusCreated, created)
	return nil
}

// handleDirectoryRoleBind serves POST /v1/directory/users/{id}/roles: bind one
// role (by slug) to a user of the caller's tenant, tenant-wide or — with
// scope_type org/team/project and scope_id — delegated to that branch of the
// hierarchy. Idempotent.
func (s *Server) handleDirectoryRoleBind(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.pool == nil {
		return apierror.NotFound("not found")
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		return apierror.Validation("user id is required")
	}
	var in struct {
		Role      string `json:"role"`
		ScopeType string `json:"scope_type"`
		ScopeID   string `json:"scope_id"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	slug := strings.ToLower(strings.TrimSpace(in.Role))
	if slug == "" {
		return apierror.Validation("role is required")
	}
	scopeType, scopeID, err := directoryScope(in.ScopeType, in.ScopeID)
	if err != nil {
		return err
	}
	// AUTHZ-09: ir-investigator is a separation-of-duty group (migration 0081).
	// It must be populated through the SCIM group-binding surface, never through
	// this directory-write API — otherwise any directory.write holder (incl. a
	// tenant admin binding the role to themselves) defeats the SoD, letting them
	// reveal encrypted IR attribution.
	if restrictedDirectoryRole(slug) {
		return apierror.Forbidden("the ir-investigator role is a separation-of-duty group and can only be assigned through SCIM")
	}
	var updated directoryUser
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		u, err := (store.Users{}).Get(ctx, sc, id)
		if err != nil {
			return apierror.NotFound("user not found")
		}
		role, err := (store.Roles{}).GetBySlug(ctx, sc, slug)
		if err != nil {
			return apierror.NotFound("role not found")
		}
		audit := map[string]any{"user_id": u.ID, "email": u.Email, "role": role.Slug}
		if scopeType == "" {
			err = (store.RoleBindings{}).Bind(ctx, sc, "user", u.ID, role.ID)
		} else {
			// The branch must exist in THIS tenant: row-level security makes
			// another tenant's org/team/project as absent as a made-up id.
			exists, existsErr := (store.RoleBindings{}).ScopeExists(ctx, sc, scopeType, scopeID)
			if existsErr != nil {
				return existsErr
			}
			if !exists {
				return apierror.NotFound(scopeType + " not found")
			}
			err = (store.RoleBindings{}).BindScoped(ctx, sc, "user", u.ID, role.ID, scopeType, scopeID)
			audit["scope_type"], audit["scope_id"] = scopeType, scopeID
		}
		if err != nil {
			return err
		}
		updated, err = s.directoryUserWithRoles(ctx, sc, u)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "directory.role_bind", tid, audit)
	}); err != nil {
		return s.directoryFailure(tid, "bind role", err)
	}
	writeJSON(w, http.StatusOK, updated)
	return nil
}

// handleDirectoryRoleUnbind serves DELETE /v1/directory/users/{id}/roles/{role};
// ?scope_type=&scope_id= removes an org/team/project-scoped grant instead of
// the tenant-wide one. The tenant's last administrator cannot be removed (a
// locked-out tenant would need the control host to recover it).
func (s *Server) handleDirectoryRoleUnbind(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.pool == nil {
		return apierror.NotFound("not found")
	}
	id := strings.TrimSpace(r.PathValue("id"))
	slug := strings.ToLower(strings.TrimSpace(r.PathValue("role")))
	if id == "" || slug == "" {
		return apierror.Validation("user id and role are required")
	}
	scopeType, scopeID, err := directoryScope(r.URL.Query().Get("scope_type"), r.URL.Query().Get("scope_id"))
	if err != nil {
		return err
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		u, err := (store.Users{}).Get(ctx, sc, id)
		if err != nil {
			return apierror.NotFound("user not found")
		}
		role, err := (store.Roles{}).GetBySlug(ctx, sc, slug)
		if err != nil {
			return apierror.NotFound("role not found")
		}
		if scopeType != "" {
			if err := (store.RoleBindings{}).UnbindScoped(ctx, sc, "user", u.ID, role.ID, scopeType, scopeID); err != nil {
				return err
			}
			return s.recordAudit(ctx, sc, r, "directory.role_unbind", tid, map[string]any{
				"user_id": u.ID, "email": u.Email, "role": role.Slug, "scope_type": scopeType, "scope_id": scopeID,
			})
		}
		if role.Slug == directoryAdminRole {
			members, err := (store.RoleBindings{}).MembersOfRole(ctx, sc, role.ID)
			if err != nil {
				return err
			}
			if len(members) == 1 && members[0] == u.ID {
				return apierror.Conflict("cannot remove the last administrator of the tenant; grant another administrator first")
			}
		}
		if err := (store.RoleBindings{}).Unbind(ctx, sc, "user", u.ID, role.ID); err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "directory.role_unbind", tid, map[string]any{
			"user_id": u.ID, "email": u.Email, "role": role.Slug,
		})
	}); err != nil {
		return s.directoryFailure(tid, "unbind role", err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
