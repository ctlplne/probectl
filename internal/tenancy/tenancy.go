// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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

// ProviderRole is the least-privilege Postgres role the provider/management
// plane assumes (S-T1). Its grants are deliberately minimal: SELECT over agents
// (via the explicit provider_fleet_read policy) + the tenant registry + the
// provider-plane tables. It can NEVER read tests, results, incidents, or any
// telemetry table — the storage layer itself confines the provider plane to
// operational metadata (docs/guardrails.md G7-1).
const ProviderRole = "probectl_provider"

// InProvider runs fn inside a transaction bound to the provider plane's
// restricted role. It is the ONLY sanctioned cross-tenant data path, and it is
// cross-tenant solely for the tables that role is granted (fleet/lifecycle
// metadata). No tenant GUC is set: the tenant_isolation policies correctly
// match nothing, and only the explicit provider policies apply.
func InProvider(ctx context.Context, pool *pgxpool.Pool, fn func(context.Context, Querier) error) error {
	tx, err := BeginProvider(ctx, pool)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit provider tx: %w", err)
	}
	return nil
}

// BeginProvider opens a transaction already bound to the provider role, for a
// provider-domain caller that manages its own commit (multi-step audit-chain
// work). The serve login can assume the role but never inherits it, so every
// provider-domain statement runs inside such a transaction (TEN-01). The
// caller must Commit or Rollback.
func BeginProvider(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin provider tx: %w", err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{ProviderRole}.Sanitize()); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("assume provider role: %w", err)
	}
	if err := runTxGuard(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

// InTenant runs fn inside a transaction bound to the tenant resolved from ctx. It
// assumes the least-privilege AppRole and sets the probectl.tenant_id GUC so
// Postgres Row-Level Security scopes every statement to this tenant. It fails
// closed when no tenant is in context (docs/guardrails.md G7-1).
func InTenant(ctx context.Context, pool *pgxpool.Pool, fn func(context.Context, Scope) error) error {
	id, ok := FromContext(ctx)
	if !ok {
		return ErrNoTenant
	}
	// D-62: a quarantined tenant's transaction is refused before it begins
	// (the silo router refuses it too; this holds even under another router).
	if err := pgQuarantineCheck(ctx, id.String()); err != nil {
		return err
	}

	// Resolve the tenant's isolation targets FIRST (fail closed: a siloed
	// tenant must never silently fall through to the pooled schema — S-T2).
	schema, err := pgSchemaFor(ctx, id.String())
	if err != nil {
		return err
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
	// Siloed tenants (S-T2): route tenant-owned tables to the tenant's own
	// schema. public stays on the path for the GLOBAL tables (permissions,
	// tenants); the tenant schema shadows every tenant-owned table, and the
	// recreated RLS policies + the GUC below keep even a mis-routed query
	// scoped (defense-in-depth on top of physical separation, not instead).
	if schema != "" {
		// DPR-368: Postgres accepts a missing schema on search_path, so an
		// absent silo would resolve every unqualified tenant table to public.
		if err := requireSiloSchema(ctx, tx, id.String(), schema, noticeTables(ctx)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			"SET LOCAL search_path TO "+pgx.Identifier{schema}.Sanitize()+", public"); err != nil {
			return fmt.Errorf("route tenant schema: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('probectl.tenant_id', $1, true)", id.String()); err != nil {
		return fmt.Errorf("bind tenant scope: %w", err)
	}

	if err := runTxGuard(ctx, tx); err != nil {
		return err
	}
	if err := fn(ctx, Scope{Tenant: id, Q: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant tx: %w", err)
	}
	return nil
}

// InTenantProviderMaintenance runs one narrowly-scoped storage-maintenance
// transaction in the tenant's actual PostgreSQL target as the least-privilege
// provider role. It binds routing and the tenant GUC before dropping privilege,
// so pooled and siloed tables enforce the same storage-layer tenant boundary.
//
// This is not a handler/repository escape hatch. It exists for controlled
// maintenance of app-append-only rows (currently audit retention) where the
// mutation and its mandatory tenant audit receipt must share one transaction.
// The callback still uses explicit tenant predicates as defense in depth and
// assumes probectl_app before appending the receipt.
func InTenantProviderMaintenance(
	ctx context.Context,
	pool *pgxpool.Pool,
	fn func(context.Context, Scope) error,
) error {
	id, ok := FromContext(ctx)
	if !ok {
		return ErrNoTenant
	}
	if err := pgQuarantineCheck(ctx, id.String()); err != nil {
		return err
	}
	schema, err := pgSchemaFor(ctx, id.String())
	if err != nil {
		return err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tenant provider-maintenance tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if schema != "" {
		if err := requireSiloSchema(ctx, tx, id.String(), schema, nil); err != nil {
			return err
		}
		if _, err := tx.Exec(
			ctx,
			"SET LOCAL search_path TO "+pgx.Identifier{schema}.Sanitize()+", public",
		); err != nil {
			return fmt.Errorf("route tenant provider-maintenance schema: %w", err)
		}
	}
	if _, err := tx.Exec(
		ctx,
		"SELECT set_config('probectl.tenant_id', $1, true)",
		id.String(),
	); err != nil {
		return fmt.Errorf("bind tenant provider-maintenance scope: %w", err)
	}
	if _, err := tx.Exec(
		ctx,
		"SET LOCAL ROLE "+pgx.Identifier{ProviderRole}.Sanitize(),
	); err != nil {
		return fmt.Errorf("assume provider role for tenant maintenance: %w", err)
	}
	if err := runTxGuard(ctx, tx); err != nil {
		return err
	}
	if err := fn(ctx, Scope{Tenant: id, Q: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tenant provider-maintenance tx: %w", err)
	}
	return nil
}

// ErrSiloSchemaMissing refuses a siloed tenant's transaction whose routed
// Postgres schema (or a table the caller requires in it) does not exist
// (DPR-368). Postgres accepts a missing schema on search_path and resolves
// every unqualified table to the next entry, public, so without this check
// such a transaction would read and write the POOLED tables under the
// tenant's id — the S-T2 fall-through the router exists to prevent.
var ErrSiloSchemaMissing = errors.New("tenancy: the tenant's isolated Postgres schema is missing or incomplete")

// requireSiloSchema checks, inside the tenant transaction, that schema exists
// and holds every table in tables.
func requireSiloSchema(ctx context.Context, tx pgx.Tx, tenantID, schema string, tables []string) error {
	if tables == nil {
		tables = []string{}
	}
	var schemaOK, tablesOK bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = $1),
		       NOT EXISTS (SELECT 1 FROM unnest($2::text[]) AS want(t)
		                    WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c
		                                        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		                                       WHERE n.nspname = $1 AND c.relname = want.t))`,
		schema, tables).Scan(&schemaOK, &tablesOK); err != nil {
		return fmt.Errorf("verify tenant schema: %w", err)
	}
	switch {
	case !schemaOK:
		return fmt.Errorf("%w: tenant %s is routed to schema %s, which does not exist (refusing rather than falling through to public)", ErrSiloSchemaMissing, tenantID, schema)
	case !tablesOK:
		return fmt.Errorf("%w: tenant %s's schema %s lacks %v (refusing rather than falling through to public)", ErrSiloSchemaMissing, tenantID, schema, tables)
	}
	return nil
}
