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

func (TagDefinitions) List(ctx context.Context, sc tenancy.Scope) ([]tags.Definition, error) {
	tenantID := sc.Tenant.String()
	rows, err := sc.Q.Query(ctx, `SELECT id::text,key FROM tenant_tag_definitions
		WHERE tenant_id=$1 ORDER BY key,id LIMIT $2`, tenantID, tags.MaxDefinitions+1)
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
		out = append(out, item)
		if len(out) > tags.MaxDefinitions {
			return nil, tags.ErrInvalid
		}
	}
	return out, rows.Err()
}

func (TagDefinitions) Create(ctx context.Context, sc tenancy.Scope, key string) (tags.Definition, error) {
	if err := tags.ValidateKey(key); err != nil {
		return tags.Definition{}, err
	}
	tenantID := sc.Tenant.String()
	// Serialize all tag-definition creation in this tenant before counting.
	// A concurrent pair of valid writes must not jointly exceed 64 keys.
	if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_revisions(tenant_id,revision)
		VALUES ($1,1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
		return tags.Definition{}, err
	}
	var revision int64
	if err := sc.Q.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions
		WHERE tenant_id=$1 FOR UPDATE`, tenantID).Scan(&revision); err != nil {
		return tags.Definition{}, err
	}
	var count int
	if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM tenant_tag_definitions
		WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil {
		return tags.Definition{}, err
	}
	if count >= tags.MaxDefinitions {
		return tags.Definition{}, tags.ErrInvalid
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
