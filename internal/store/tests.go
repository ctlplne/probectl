// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Test is a synthetic-test definition. It is tenant-scoped: RLS confines every
// row to the caller's tenant.
type Test struct {
	ID              string            `json:"id"`
	TenantID        string            `json:"tenant_id"`
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	IntervalSeconds int               `json:"interval_seconds"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	Params          map[string]string `json:"params"`
	Enabled         bool              `json:"enabled"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// TestInput is the mutable field set for create/update.
type TestInput struct {
	Name            string
	Type            string
	Target          string
	IntervalSeconds int
	TimeoutSeconds  int
	Params          map[string]string
	Enabled         bool
}

// Tests is the tenant-scoped synthetic-test repository.
type Tests struct{}

const testCols = `id::text, tenant_id::text, name, type, target,
	interval_seconds, timeout_seconds, params, enabled, created_at, updated_at`

func scanTest(row interface{ Scan(...any) error }, t *Test) error {
	var params []byte
	if err := row.Scan(&t.ID, &t.TenantID, &t.Name, &t.Type, &t.Target,
		&t.IntervalSeconds, &t.TimeoutSeconds, &params, &t.Enabled, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return err
	}
	t.Params = map[string]string{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &t.Params); err != nil {
			return err
		}
	}
	return nil
}

func marshalParams(p map[string]string) (string, error) {
	if p == nil {
		p = map[string]string{}
	}
	b, err := json.Marshal(p)
	return string(b), err
}

// Create inserts a test in the caller's tenant.
func (Tests) Create(ctx context.Context, s tenancy.Scope, in TestInput) (*Test, error) {
	params, err := marshalParams(in.Params)
	if err != nil {
		return nil, err
	}
	var t Test
	err = scanTest(s.Q.QueryRow(ctx,
		`INSERT INTO tests (tenant_id, name, type, target, interval_seconds, timeout_seconds, params, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
		 RETURNING `+testCols,
		s.Tenant.String(), in.Name, in.Type, in.Target, in.IntervalSeconds, in.TimeoutSeconds, params, in.Enabled), &t)
	if err != nil {
		return nil, mapWriteErr("test", err)
	}
	return &t, nil
}

// Get returns a test by id (RLS guarantees it belongs to the tenant).
func (Tests) Get(ctx context.Context, s tenancy.Scope, id string) (*Test, error) {
	var t Test
	if err := scanTest(s.Q.QueryRow(ctx, `SELECT `+testCols+` FROM tests WHERE id = $1`, id), &t); err != nil {
		return nil, notFound("test", err)
	}
	return &t, nil
}

// Exists reports whether the tenant has at least one synthetic test.
func (Tests) Exists(ctx context.Context, s tenancy.Scope) (bool, error) {
	var ok bool
	err := s.Q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tests)`).Scan(&ok)
	return ok, err
}

// DefaultTestPageSize bounds an unspecified tests page (SCALE-002). Mirrors
// Agents.DefaultAgentPageSize — the tests table had no LIMIT while agents did.
const DefaultTestPageSize = 200

// maxTestPageSize is the hard cap on a single tests page (SCALE-002).
const maxTestPageSize = 1000

// List returns the tenant's tests, newest first. DEPRECATED for unbounded use:
// callers that materialize the whole set must page via ListPage/ListAll
// (SCALE-002) so a tenant with 50k tests cannot load the entire table in one
// query. Retained for small internal call sites that page through it.
func (Tests) List(ctx context.Context, s tenancy.Scope) ([]Test, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+testCols+` FROM tests ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Test{}
	for rows.Next() {
		var t Test
		if err := scanTest(rows, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListPage returns one cursor page of tests ordered by id, starting AFTER the
// given cursor id (empty = first page), capped at limit (SCALE-002). Mirrors
// Agents.ListPage: id ordering is stable (UUID PK), so the next cursor is the
// last returned id. This is what /v1/tests and the bounded internal full-set
// scans use so an unbounded SELECT * never lands on the hot path.
func (Tests) ListPage(ctx context.Context, s tenancy.Scope, afterID string, limit int) ([]Test, error) {
	if limit <= 0 || limit > maxTestPageSize {
		limit = DefaultTestPageSize
	}
	// SCALE-002: empty cursor = first page. id is a uuid PK, so we must NOT bind
	// "" to `id > $1` (Postgres rejects an empty string as uuid, SQLSTATE 22P02);
	// omit the cursor predicate entirely on the first page.
	q := `SELECT ` + testCols + ` FROM tests WHERE id > $1 ORDER BY id LIMIT $2`
	args := []any{afterID, limit}
	if afterID == "" {
		q = `SELECT ` + testCols + ` FROM tests ORDER BY id LIMIT $1`
		args = []any{limit}
	}
	rows, err := s.Q.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Test{}
	for rows.Next() {
		var t Test
		if err := scanTest(rows, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListAll materializes every test for the tenant by paging through ListPage in
// bounded chunks (SCALE-002). Internal call sites that genuinely need the whole
// set (the signed test-sync bundle, AI authoring's existing-target dedup, the
// MCP test list) use this instead of an unbounded SELECT *: the wire query stays
// LIMIT-bounded even though the result is the full set. maxRows is a safety
// ceiling (0 = no extra ceiling beyond paging).
func (t Tests) ListAll(ctx context.Context, s tenancy.Scope, maxRows int) ([]Test, error) {
	var out []Test
	cursor := ""
	for {
		page, err := t.ListPage(ctx, s, cursor, maxTestPageSize)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < maxTestPageSize {
			break // last (partial) page
		}
		cursor = page[len(page)-1].ID
		if maxRows > 0 && len(out) >= maxRows {
			break
		}
	}
	return out, nil
}

// Update replaces a test's mutable fields.
func (Tests) Update(ctx context.Context, s tenancy.Scope, id string, in TestInput) (*Test, error) {
	params, err := marshalParams(in.Params)
	if err != nil {
		return nil, err
	}
	var t Test
	err = scanTest(s.Q.QueryRow(ctx,
		`UPDATE tests SET name = $2, type = $3, target = $4, interval_seconds = $5,
		   timeout_seconds = $6, params = $7::jsonb, enabled = $8, updated_at = now()
		 WHERE id = $1
		 RETURNING `+testCols,
		id, in.Name, in.Type, in.Target, in.IntervalSeconds, in.TimeoutSeconds, params, in.Enabled), &t)
	if err != nil {
		return nil, mapWriteErr("test", err)
	}
	return &t, nil
}

// Delete removes a test by id.
func (Tests) Delete(ctx context.Context, s tenancy.Scope, id string) error {
	tag, err := s.Q.Exec(ctx, `DELETE FROM tests WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return apierror.NotFound("test not found")
	}
	return nil
}

// mapWriteErr maps a unique-violation to Conflict and a no-rows to NotFound;
// other errors pass through.
func mapWriteErr(entity string, err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" { // unique_violation
		return apierror.Conflict(entity + " name already exists")
	}
	return notFound(entity, err)
}
