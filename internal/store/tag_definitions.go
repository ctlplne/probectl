// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TagDefinitions mutates only the authenticated tenant's vocabulary through
// a tenant transaction. FORCE RLS, a tenant-qualified key and the write fence
// are the outer boundary; the handler appends audit in the same transaction.
type TagDefinitions struct{}

// List is the library default; public surfaces pass the operator's live profile
// to ListBounded. Byte admission is finite and does not truncate the vocabulary.
func (s TagDefinitions) List(ctx context.Context, sc tenancy.Scope) ([]tags.Definition, error) {
	return s.ListBounded(ctx, sc, 64<<20)
}

func (TagDefinitions) ListBounded(ctx context.Context, sc tenancy.Scope, maxBytes int64) ([]tags.Definition, error) {
	if maxBytes <= 0 {
		return nil, ErrTagSnapshotBudget
	}
	used := int64(0)
	tenantID := sc.Tenant.String()
	rows, err := sc.Q.Query(ctx, `SELECT id::text,key FROM tenant_tag_definitions
		WHERE tenant_id=$1 ORDER BY key,id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]tags.Definition, 0)
	for rows.Next() {
		item := tags.Definition{TenantID: tenantID}
		if err := rows.Scan(&item.ID, &item.Key); err != nil {
			return nil, err
		}
		// Include the seven derived field variants and their maps/slices before
		// any caller expands this definition into a query vocabulary.
		cost := int64(8192 + len(item.ID) + len(item.Key))
		if cost > maxBytes-used {
			return nil, ErrTagSnapshotBudget
		}
		used += cost
		out = append(out, item)
	}
	return out, rows.Err()
}

func (TagDefinitions) Create(ctx context.Context, sc tenancy.Scope, key string) (tags.Definition, error) {
	if err := tags.ValidateKey(key); err != nil {
		return tags.Definition{}, err
	}
	tenantID := sc.Tenant.String()
	// Serialize tag mutations with the tenant revision and its audit event.
	// Persisted cardinality is not an independent product quota.
	if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_revisions(tenant_id,revision)
		VALUES ($1,1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
		return tags.Definition{}, err
	}
	var revision int64
	if err := sc.Q.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions
		WHERE tenant_id=$1 FOR UPDATE`, tenantID).Scan(&revision); err != nil {
		return tags.Definition{}, err
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return tags.Definition{}, err
	}
	item := tags.Definition{TenantID: tenantID, ID: id, Key: key}
	if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key)
		VALUES ($1,$2,$3)`, tenantID, id, key); err != nil {
		return tags.Definition{}, tagDefinitionError(err)
	}
	return item, nil
}

func (TagDefinitions) Rename(ctx context.Context, sc tenancy.Scope, id, key string) (tags.Definition, error) {
	if err := tags.ValidateKey(key); err != nil {
		return tags.Definition{}, err
	}
	tenantID := sc.Tenant.String()
	item := tags.Definition{TenantID: tenantID}
	err := sc.Q.QueryRow(ctx, `UPDATE tenant_tag_definitions SET key=$3
		WHERE tenant_id=$1 AND id=$2 RETURNING id::text,key`, tenantID, id, key).
		Scan(&item.ID, &item.Key)
	if err != nil {
		return tags.Definition{}, tagDefinitionError(err)
	}
	return item, nil
}

func (TagDefinitions) Delete(ctx context.Context, sc tenancy.Scope, id string) error {
	result, err := sc.Q.Exec(ctx, `DELETE FROM tenant_tag_definitions
		WHERE tenant_id=$1 AND id=$2`, sc.Tenant.String(), id)
	if err != nil {
		return tagDefinitionError(err)
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func tagDefinitionError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return tags.ErrConflict
		case "23514", "22P02":
			return tags.ErrInvalid
		}
	}
	return err
}
