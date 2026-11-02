// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PostgresQueryFilterStore persists reusable query configuration under FORCE
// RLS. The explicit tenant predicate remains a second lock on every operation.
type PostgresQueryFilterStore struct {
	recordAudit       QueryConfigAudit
	pool              *pgxpool.Pool
	fence             tenancy.WriterFence
	maxBytesPerTenant int
	now               func() time.Time
}

// NewPostgresQueryFilterStore uses the existing durable lifecycle write fence.
func NewPostgresQueryFilterStore(pool *pgxpool.Pool, maxBytesPerTenant int, recordAudit QueryConfigAudit) *PostgresQueryFilterStore {
	if maxBytesPerTenant <= 0 {
		maxBytesPerTenant = 64 << 20
	}
	return &PostgresQueryFilterStore{recordAudit: recordAudit, pool: pool, fence: tenancy.NewPostgresWriterFence(pool), maxBytesPerTenant: maxBytesPerTenant, now: time.Now}
}

func (s *PostgresQueryFilterStore) inTenant(ctx context.Context, tenant string, fn func(context.Context, tenancy.Scope) error) error {
	if strings.TrimSpace(tenant) == "" {
		return errors.New("saved flow filter tenant is required")
	}
	if s == nil || s.pool == nil {
		return errors.New("saved flow filter storage is unavailable")
	}
	return tenancy.InTenant(tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(tenant))), s.pool, fn)
}

const queryFilterColumns = `id::text,tenant_id::text,name,description,expression,version,updated_by,created_at,updated_at`

type queryFilterScanner interface{ Scan(...any) error }

func scanQueryFilter(ctx context.Context, row queryFilterScanner) (SavedQueryFilter, error) {
	var item SavedQueryFilter
	var expression []byte
	if err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.Description, &expression, &item.Version, &item.UpdatedBy, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return SavedQueryFilter{}, err
	}
	if len(expression) > 2*MaxPlanGrammarBytes {
		return SavedQueryFilter{}, ErrQueryFilterStorageBudget
	}
	decoder := json.NewDecoder(bytes.NewReader(expression))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&item.Expression); err != nil {
		return SavedQueryFilter{}, errors.New("stored flow filter expression is invalid")
	}
	return cloneSavedQueryFilter(ctx, item)
}

func queryFilterStorageError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrQueryFilterNotFound
	}
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) && postgres.Code == "22P02" {
		return ErrQueryFilterNotFound
	}
	return err
}

type scopedQueryFilterReader struct{ scope tenancy.Scope }

func (r scopedQueryFilterReader) GetQueryFilter(ctx context.Context, tenant, id string) (SavedQueryFilter, error) {
	item, err := scanQueryFilter(ctx, r.scope.Q.QueryRow(ctx, `SELECT `+queryFilterColumns+` FROM flow_query_filters WHERE tenant_id=$1::uuid AND id=$2::uuid`, tenant, id))
	return item, queryFilterStorageError(err)
}

// GetQueryFilter resolves only the authenticated tenant's configuration row.
func (s *PostgresQueryFilterStore) GetQueryFilter(ctx context.Context, tenant, id string) (SavedQueryFilter, error) {
	var result SavedQueryFilter
	err := s.inTenant(ctx, tenant, func(ctx context.Context, scope tenancy.Scope) error {
		var err error
		result, err = (scopedQueryFilterReader{scope}).GetQueryFilter(ctx, tenant, id)
		return err
	})
	return result, queryFilterStorageError(err)
}

// SaveQueryFilter serializes tenant configuration mutations so dependency
// validation cannot race another mutation into a reference cycle.
func (s *PostgresQueryFilterStore) SaveQueryFilter(ctx context.Context, tenant, actor string, input SaveQueryFilter) (SavedQueryFilter, error) {
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(actor) == "" {
		return SavedQueryFilter{}, errors.New("saved flow filter requires tenant and actor")
	}
	input, err := normalizeSaveQueryFilterForTenant(ctx, tenant, input)
	if err != nil {
		return SavedQueryFilter{}, err
	}
	var result SavedQueryFilter
	err = tenancy.FencedWrite(ctx, s.fence, []string{tenant}, func(tenant string) string { return tenant }, errors.New("saved flow filter tenant is required"), func(ctx context.Context) error {
		return s.inTenant(ctx, tenant, func(ctx context.Context, scope tenancy.Scope) error {
			if _, err := scope.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('probectl.flow_query_filters:' || $1::text,0))`, tenant); err != nil {
				return err
			}
			previous := SavedQueryFilter{}
			if input.ID != "" {
				var err error
				previous, err = (scopedQueryFilterReader{scope}).GetQueryFilter(ctx, tenant, input.ID)
				if err != nil {
					return err
				}
				if previous.Version != input.Version {
					return ErrQueryFilterConflict
				}
			}
			if previous.Version == math.MaxInt64 {
				return ErrQueryFilterConflict
			}
			if _, err := resolveQueryFiltersForTenant(ctx, tenant, &input.Expression, scopedQueryFilterReader{scope}, input.ID); err != nil {
				return err
			}
			expression, err := json.Marshal(input.Expression)
			if err != nil {
				return err
			}
			var expressionBytes int64
			if err := scope.Q.QueryRow(ctx, `SELECT octet_length($1::jsonb::text)`, string(expression)).Scan(&expressionBytes); err != nil {
				return err
			}
			var bytesUsed int64
			if err := scope.Q.QueryRow(ctx, `SELECT COALESCE(sum(octet_length(expression::text)+octet_length(name)+octet_length(description)+octet_length(updated_by)+128),0)::bigint FROM flow_query_filters WHERE tenant_id=$1::uuid AND ($2='' OR id::text<>$2)`, tenant, input.ID).Scan(&bytesUsed); err != nil {
				return err
			}
			if bytesUsed+expressionBytes+int64(len(input.Name)+len(input.Description)+len(actor)+128) > int64(s.maxBytesPerTenant) {
				return ErrQueryFilterStorageBudget
			}
			id := input.ID
			now := s.now().UTC()
			created := previous.CreatedAt
			if id == "" {
				id, err = crypto.UUIDv4()
				if err != nil {
					return err
				}
				created = now
			}
			result = SavedQueryFilter{ID: id, TenantID: tenant, Name: input.Name, Description: input.Description, Expression: input.Expression, Version: previous.Version + 1, UpdatedBy: actor, CreatedAt: created, UpdatedAt: now}
			if input.ID == "" {
				_, err = scope.Q.Exec(ctx, `INSERT INTO flow_query_filters(tenant_id,id,name,description,expression,version,updated_by,created_at,updated_at) VALUES($1::uuid,$2::uuid,$3,$4,$5::jsonb,1,$6,$7,$7)`, tenant, id, input.Name, input.Description, string(expression), actor, now)
			} else {
				command, updateErr := scope.Q.Exec(ctx, `UPDATE flow_query_filters SET name=$3,description=$4,expression=$5::jsonb,version=version+1,updated_by=$6,updated_at=$7 WHERE tenant_id=$1::uuid AND id=$2::uuid AND version=$8`, tenant, id, input.Name, input.Description, string(expression), actor, now, input.Version)
				err = updateErr
				if err == nil && command.RowsAffected() != 1 {
					return ErrQueryFilterConflict
				}
			}
			if err != nil {
				return err
			}
			action := "flow.filter.create"
			if input.ID != "" {
				action = "flow.filter.update"
			}
			err = recordQueryConfig(ctx, scope, s.recordAudit, actor, action, id, map[string]any{"version": result.Version, "expression_hash": fmt.Sprintf("%x", crypto.Hash(expression))})
			return err
		})
	})
	if err != nil {
		return SavedQueryFilter{}, queryFilterStorageError(err)
	}
	return cloneSavedQueryFilter(ctx, result)
}

// ListQueryFilters returns an explicit next cursor rather than concealing a
// truncated list. Row scope and ordering both lead with the bound tenant.
func (s *PostgresQueryFilterStore) ListQueryFilters(ctx context.Context, tenant, after string, limit int) (QueryFilterPage, error) {
	if limit < 1 || limit > 1000 {
		return QueryFilterPage{}, errors.New("saved flow filter page size must be 1-1000")
	}
	page := QueryFilterPage{Items: []SavedQueryFilter{}}
	err := s.inTenant(ctx, tenant, func(ctx context.Context, scope tenancy.Scope) error {
		rows, err := scope.Q.Query(ctx, `SELECT `+queryFilterColumns+` FROM flow_query_filters WHERE tenant_id=$1::uuid AND id::text>$2 ORDER BY id LIMIT $3`, tenant, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		bytesUsed := 0
		for rows.Next() {
			item, err := scanQueryFilter(ctx, rows)
			if err != nil {
				return err
			}
			more, err := appendQueryFilterPage(&page, item, limit, maxQueryFilterPageBytes, &bytesUsed)
			if err != nil {
				return err
			}
			if more {
				break
			}
		}
		return rows.Err()
	})
	if err != nil {
		return QueryFilterPage{}, fmt.Errorf("list saved flow filters: %w", err)
	}
	return page, nil
}

// DeleteQueryFilter preserves the lifecycle write barrier and version check.
func (s *PostgresQueryFilterStore) DeleteQueryFilter(ctx context.Context, tenant, actor, id string, version int64) error {
	if strings.TrimSpace(actor) == "" {
		return errors.New("saved flow filter actor is required")
	}
	if version < 1 {
		return ErrQueryFilterConflict
	}
	return tenancy.FencedWrite(ctx, s.fence, []string{tenant}, func(tenant string) string { return tenant }, errors.New("saved flow filter tenant is required"), func(ctx context.Context) error {
		return s.inTenant(ctx, tenant, func(ctx context.Context, scope tenancy.Scope) error {
			if _, err := scope.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('probectl.flow_query_filters:' || $1::text,0))`, tenant); err != nil {
				return err
			}
			item, err := (scopedQueryFilterReader{scope}).GetQueryFilter(ctx, tenant, id)
			if err != nil {
				return err
			}
			if item.Version != version {
				return ErrQueryFilterConflict
			}
			command, err := scope.Q.Exec(ctx, `DELETE FROM flow_query_filters WHERE tenant_id=$1::uuid AND id=$2::uuid AND version=$3`, tenant, id, version)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrQueryFilterConflict
			}
			err = recordQueryConfig(ctx, scope, s.recordAudit, actor, "flow.filter.delete", id, map[string]any{"version": version})
			return err
		})
	})
}
