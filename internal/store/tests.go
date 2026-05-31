package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/imfeelingtheagi/netctl/internal/apierror"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
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

// List returns the tenant's tests, newest first.
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
