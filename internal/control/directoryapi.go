// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	return directoryUser{User: *u, Roles: slugs}, nil
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
		users, n, err := (store.Users{}).ListPage(ctx, sc, "", 1, directoryListMax)
		if err != nil {
			return err
		}
		byUser, err := (store.RoleBindings{}).RoleSlugsByUser(ctx, sc)
		if err != nil {
			return err
		}
		total = n
		for i := range users {
			slugs := byUser[users[i].ID]
			if slugs == nil {
				slugs = []string{}
			}
			out = append(out, directoryUser{User: users[i], Roles: slugs})
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
// role (by slug) to a user of the caller's tenant. Idempotent.
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
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	slug := strings.ToLower(strings.TrimSpace(in.Role))
	if slug == "" {
		return apierror.Validation("role is required")
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
		if err := (store.RoleBindings{}).Bind(ctx, sc, "user", u.ID, role.ID); err != nil {
			return err
		}
		updated, err = s.directoryUserWithRoles(ctx, sc, u)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "directory.role_bind", tid, map[string]any{
			"user_id": u.ID, "email": u.Email, "role": role.Slug,
		})
	}); err != nil {
		return s.directoryFailure(tid, "bind role", err)
	}
	writeJSON(w, http.StatusOK, updated)
	return nil
}

// handleDirectoryRoleUnbind serves DELETE /v1/directory/users/{id}/roles/{role}.
// The tenant's last administrator cannot be removed (a locked-out tenant would
// need the control host to recover it).
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
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		u, err := (store.Users{}).Get(ctx, sc, id)
		if err != nil {
			return apierror.NotFound("user not found")
		}
		role, err := (store.Roles{}).GetBySlug(ctx, sc, slug)
		if err != nil {
			return apierror.NotFound("role not found")
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
