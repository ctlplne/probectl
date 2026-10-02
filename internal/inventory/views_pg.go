// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// PostgresViewStore is the durable saved-view store (PLAT-06): inventory saved
// views survive a control-plane restart and are shared across replicas, unlike
// MemoryViewStore. Every operation runs inside a tenant-scoped transaction, so
// FORCE ROW LEVEL SECURITY (migration 0105) is the enforced boundary; owner
// scoping is layered on top within the tenant.
type PostgresViewStore struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewPostgresViewStore binds the store to the writer pool.
func NewPostgresViewStore(pool *pgxpool.Pool) *PostgresViewStore {
	return &PostgresViewStore{pool: pool, now: time.Now}
}

func (s *PostgresViewStore) inTenant(ctx context.Context, tenant string, fn func(context.Context, tenancy.Scope) error) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), s.pool, fn)
}

func (s *PostgresViewStore) Save(ctx context.Context, tenantID, ownerID string, input SaveViewInput) (SavedView, error) {
	if strings.TrimSpace(tenantID) == "" {
		return SavedView{}, errors.New("inventory saved view: tenant_id is required")
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return SavedView{}, errors.New("inventory saved view: owner_id is required")
	}
	input, err := cleanInput(input)
	if err != nil {
		return SavedView{}, err
	}
	filters, err := json.Marshal(copyFilters(input.Filters))
	if err != nil {
		return SavedView{}, fmt.Errorf("inventory saved view: encode filters: %w", err)
	}
	now := s.now().UTC()
	view := SavedView{
		TenantID: tenantID, OwnerID: ownerID, Surface: input.Surface, Name: input.Name,
		Filters: copyFilters(input.Filters), CreatedAt: now, UpdatedAt: now,
	}
	err = s.inTenant(ctx, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `
INSERT INTO inventory_saved_views (tenant_id, owner_id, surface, name, filters, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $6)
RETURNING id::text`, tenantID, ownerID, input.Surface, input.Name, string(filters), now).Scan(&view.ID)
	})
	if err != nil {
		return SavedView{}, fmt.Errorf("inventory saved view: save: %w", err)
	}
	if view.Filters == nil {
		view.Filters = map[string]string{}
	}
	return view, nil
}

func (s *PostgresViewStore) List(ctx context.Context, tenantID, ownerID, surface string) ([]SavedView, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("inventory saved view: tenant_id is required")
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return nil, errors.New("inventory saved view: owner_id is required")
	}
	surface = strings.ToLower(strings.TrimSpace(surface))
	out := []SavedView{}
	err := s.inTenant(ctx, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `
SELECT id::text, tenant_id::text, owner_id, surface, name, filters, created_at, updated_at
  FROM inventory_saved_views
 WHERE owner_id = $1 AND ($2 = '' OR surface = $2)
 ORDER BY created_at DESC, name ASC`, ownerID, surface)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			view, err := scanView(rows)
			if err != nil {
				return err
			}
			out = append(out, view)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("inventory saved view: list: %w", err)
	}
	return out, nil
}

func (s *PostgresViewStore) Get(ctx context.Context, tenantID, ownerID, id string) (SavedView, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return SavedView{}, errors.New("inventory saved view: owner_id is required")
	}
	var view SavedView
	err := s.inTenant(ctx, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
		row := sc.Q.QueryRow(ctx, `
SELECT id::text, tenant_id::text, owner_id, surface, name, filters, created_at, updated_at
  FROM inventory_saved_views
 WHERE id = $1::uuid AND owner_id = $2`, id, ownerID)
		v, err := scanView(row)
		if err != nil {
			return err
		}
		view = v
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SavedView{}, ErrNotFound
	}
	if err != nil {
		// A malformed (non-uuid) id can never match; surface it as not-found.
		if strings.Contains(err.Error(), "invalid input syntax for type uuid") {
			return SavedView{}, ErrNotFound
		}
		return SavedView{}, fmt.Errorf("inventory saved view: get: %w", err)
	}
	return view, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanView(r rowScanner) (SavedView, error) {
	var v SavedView
	var filters []byte
	if err := r.Scan(&v.ID, &v.TenantID, &v.OwnerID, &v.Surface, &v.Name, &filters, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return SavedView{}, err
	}
	v.Filters = map[string]string{}
	if len(filters) > 0 {
		_ = json.Unmarshal(filters, &v.Filters)
	}
	v.CreatedAt = v.CreatedAt.UTC()
	v.UpdatedAt = v.UpdatedAt.UTC()
	return v, nil
}
