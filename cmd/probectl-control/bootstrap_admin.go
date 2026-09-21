// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// bootstrapAdminActor is the audit actor recorded for the control-host
// bootstrap grant: it is an operator action on the database host, not a
// session, so it is named as such rather than impersonating a user.
const bootstrapAdminActor = "system:bootstrap-admin"

// runBootstrapAdmin implements `probectl-control bootstrap-admin` (DPR-013):
// the first explicit role grant on a fresh session-auth deployment. SSO
// provisions every user with no roles (deny-by-default), so the very first
// tenant administrator has no way in — there is no admin yet to grant the
// role, and SCIM group sync may not exist. This command runs on the control
// host with database access (the same trust as `migrate` or `mcp-token`),
// creates the user row if the person has not logged in yet, binds the role
// at tenant scope, and records an `rbac.bind` audit event in the same
// tenant-scoped transaction. It is idempotent: re-running it for a user who
// already holds the role changes nothing.
func runBootstrapAdmin(ctx context.Context, db *store.DB, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	tenant := fs.String("tenant", tenancy.DefaultTenantID.String(), "tenant id (uuid)")
	email := fs.String("email", "", "the person's SSO email (required); the user row is created if they have not logged in yet")
	role := fs.String("role", "admin", "role slug to bind: admin | editor | viewer (or a custom role)")
	displayName := fs.String("display-name", "", "display name used only when the user row is created")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return bootstrapAdmin(ctx, db, log, *tenant, *email, *role, *displayName)
}

func bootstrapAdmin(ctx context.Context, db *store.DB, log *slog.Logger, tenant, email, role, displayName string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	role = strings.TrimSpace(role)
	if email == "" || !strings.Contains(email, "@") {
		return fmt.Errorf("bootstrap-admin: -email <sso-email> is required")
	}
	if role == "" {
		return fmt.Errorf("bootstrap-admin: -role must not be empty")
	}
	if _, err := uuid.Parse(strings.TrimSpace(tenant)); err != nil {
		return fmt.Errorf("bootstrap-admin: -tenant must be a tenant uuid: %w", err)
	}
	tid := tenancy.ID(strings.ToLower(strings.TrimSpace(tenant)))
	var (
		created bool
		userID  string
	)
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tid), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		u, err := store.Users{}.GetByEmail(ctx, sc, email)
		if err != nil {
			de, ok := apierror.As(err)
			if !ok || de.Kind != apierror.KindNotFound {
				return err
			}
			name := displayName
			if name == "" {
				name = email
			}
			u, err = store.Users{}.Create(ctx, sc, email, name)
			if err != nil {
				return err
			}
			created = true
		}
		userID = u.ID
		// DPR-035: a tenant provisioned before system roles were seeded at
		// publication has no role to bind; seeding is idempotent, so do it
		// here rather than fail the very first grant.
		if err := (store.Roles{}).EnsureSystemRoles(ctx, sc); err != nil {
			return fmt.Errorf("seed system roles: %w", err)
		}
		r, err := store.Roles{}.GetBySlug(ctx, sc, role)
		if err != nil {
			return fmt.Errorf("role %q: %w (seeded roles are admin, editor, viewer)", role, err)
		}
		if err := (store.RoleBindings{}).Bind(ctx, sc, "user", u.ID, r.ID); err != nil {
			return err
		}
		_, err = audit.TenantAppend(ctx, sc, bootstrapAdminActor, "rbac.bind", u.ID, map[string]any{
			"email": email, "role": role, "user_created": created, "source": "bootstrap-admin",
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("bootstrap-admin: %w", err)
	}
	log.Info("bootstrap-admin: role bound", "tenant", tid.String(), "user", userID, "email", email, "role", role, "user_created", created)
	fmt.Printf("bound role %q to %s in tenant %s (user %s%s)\n", role, email, tid.String(), userID, map[bool]string{true: ", created", false: ""}[created])
	return nil
}
