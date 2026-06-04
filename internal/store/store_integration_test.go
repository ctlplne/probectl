//go:build integration

package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func dsn() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://probectl@localhost:5432/postgres?sslmode=disable"
}

func setup(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

func inTenant(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id string, fn func(context.Context, tenancy.Scope) error) {
	t.Helper()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id)), pool, fn); err != nil {
		t.Fatalf("InTenant(%s): %v", id, err)
	}
}

func TestTenantLifecycle(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	repo := NewTenants(pool)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tn, err := repo.Create(ctx, "crud-"+sfx, "CRUD Tenant")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got, err := repo.Get(ctx, tn.ID); err != nil || got.Slug != tn.Slug {
		t.Fatalf("get: %v / %+v", err, got)
	}
	if got, err := repo.GetBySlug(ctx, "crud-"+sfx); err != nil || got.ID != tn.ID {
		t.Fatalf("get by slug: %v / %+v", err, got)
	}
	if susp, err := repo.UpdateStatus(ctx, tn.ID, "suspended"); err != nil || susp.Status != "suspended" {
		t.Fatalf("update status: %v / %+v", err, susp)
	}
}

func TestHierarchyAndRBACCRUD(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tn, err := NewTenants(pool).Create(ctx, "hier-"+sfx, "Hierarchy")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, s tenancy.Scope) error {
		org, err := (Organizations{}).Create(ctx, s, "eng", "Engineering")
		if err != nil {
			t.Fatalf("create org: %v", err)
		}
		team, err := (Teams{}).Create(ctx, s, org.ID, "net", "Network")
		if err != nil {
			t.Fatalf("create team: %v", err)
		}
		proj, err := (Projects{}).Create(ctx, s, team.ID, "core", "Core")
		if err != nil {
			t.Fatalf("create project: %v", err)
		}
		user, err := (Users{}).Create(ctx, s, "alice@example.com", "Alice")
		if err != nil {
			t.Fatalf("create user: %v", err)
		}

		if got, err := (Organizations{}).Get(ctx, s, org.ID); err != nil || got.Slug != "eng" {
			t.Errorf("get org: %v / %+v", err, got)
		}
		if teams, err := (Teams{}).ListByOrg(ctx, s, org.ID); err != nil || len(teams) != 1 {
			t.Errorf("list teams: %v / %d", err, len(teams))
		}
		if projs, err := (Projects{}).ListByTeam(ctx, s, team.ID); err != nil || len(projs) != 1 || projs[0].ID != proj.ID {
			t.Errorf("list projects: %v / %d", err, len(projs))
		}
		if gu, err := (Users{}).GetByEmail(ctx, s, "alice@example.com"); err != nil || gu.ID != user.ID {
			t.Errorf("get user by email: %v / %+v", err, gu)
		}

		role, err := (Roles{}).Create(ctx, s, "viewer", "Viewer", "read-only")
		if err != nil {
			t.Fatalf("create role: %v", err)
		}
		if err := (Roles{}).AddPermission(ctx, s, role.ID, "test.read"); err != nil {
			t.Fatalf("add permission: %v", err)
		}
		if perms, err := (Roles{}).Permissions(ctx, s, role.ID); err != nil || len(perms) != 1 || perms[0] != "test.read" {
			t.Errorf("permissions: %v / %v", err, perms)
		}
		if _, err := (RoleBindings{}).Create(ctx, s, "user", user.ID, role.ID, "tenant", nil); err != nil {
			t.Fatalf("create binding: %v", err)
		}
		if n, err := (RoleBindings{}).CountForSubject(ctx, s, "user", user.ID); err != nil || n != 1 {
			t.Errorf("count bindings: %v / %d", err, n)
		}
		return nil
	})
}

func TestProviderOperatorsAndBreakGlass(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tn, err := NewTenants(pool).Create(ctx, "bg-"+sfx, "BreakGlass")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	op, err := NewOperators(pool).Create(ctx, "op-"+sfx+"@example.com", "Operator")
	if err != nil {
		t.Fatalf("create operator: %v", err)
	}

	bg := NewBreakGlass(pool)
	grant, err := bg.Grant(ctx, op.ID, tn.ID, "incident-123", "read", "system", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	active, err := bg.ListActive(ctx, tn.ID)
	if err != nil || len(active) != 1 || active[0].ID != grant.ID {
		t.Fatalf("list active: %v / %+v", err, active)
	}
	if err := bg.Revoke(ctx, grant.ID, "system"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if active2, err := bg.ListActive(ctx, tn.ID); err != nil || len(active2) != 0 {
		t.Errorf("after revoke, active = %v / %+v", err, active2)
	}
}
