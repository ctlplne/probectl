package tenancy

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ID is a tenant identifier (a UUID string).
type ID string

// String returns the identifier as a string.
func (id ID) String() string { return string(id) }

// DefaultTenantID is the seeded default tenant — the single-tenant / dev case is
// just this one tenant (no separate code path; F50).
const DefaultTenantID ID = "00000000-0000-0000-0000-000000000001"

// AppRole is the least-privilege Postgres role assumed for every tenant-scoped
// transaction so RLS is enforced regardless of the connecting role.
const AppRole = "probectl_app"

// ErrNoTenant is returned (fail closed) when a tenant-scoped operation is
// attempted without a tenant in context.
var ErrNoTenant = errors.New("tenancy: no tenant in context")

type ctxKey struct{}

// WithTenant returns a context carrying the tenant identity.
func WithTenant(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the tenant identity in ctx, if present and non-empty.
func FromContext(ctx context.Context) (ID, bool) {
	id, ok := ctx.Value(ctxKey{}).(ID)
	return id, ok && id != ""
}

// Querier is the data-access surface a tenant-scoped repository uses. It is the
// pgx transaction opened by InTenant; repositories cannot commit or roll it back.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Scope is a tenant-bound data-access handle passed to repositories.
type Scope struct {
	Tenant ID
	Q      Querier
}

// InTenant runs fn inside a transaction bound to the tenant resolved from ctx. It
// assumes the least-privilege AppRole and sets the probectl.tenant_id GUC so
// Postgres Row-Level Security scopes every statement to this tenant. It fails
// closed when no tenant is in context (CLAUDE.md §7 guardrail 1).
func InTenant(ctx context.Context, pool *pgxpool.Pool, fn func(context.Context, Scope) error) error {
	id, ok := FromContext(ctx)
	if !ok {
		return ErrNoTenant
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tenant tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	// Drop to the restricted role so RLS applies, then bind the tenant. The role
	// name is a constant; quote it as an identifier for safety.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{AppRole}.Sanitize()); err != nil {
		return fmt.Errorf("assume app role: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('probectl.tenant_id', $1, true)", id.String()); err != nil {
		return fmt.Errorf("bind tenant scope: %w", err)
	}

	if err := fn(ctx, Scope{Tenant: id, Q: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant tx: %w", err)
	}
	return nil
}
