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
	"io"
	"math"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PostgresQueryViewStore uses FORCE-RLS and explicit tenant/visibility/owner
// predicates before decoding configuration. All mutation audits are atomic.
type PostgresQueryViewStore struct {
	recordAudit QueryConfigAudit
	pool        *pgxpool.Pool
	fence       tenancy.WriterFence
	maxBytes    int
	now         func() time.Time
}

func NewPostgresQueryViewStore(pool *pgxpool.Pool, maxBytes int, recordAudit QueryConfigAudit) *PostgresQueryViewStore {
	if maxBytes <= 0 {
		maxBytes = 64 << 20
	}
	return &PostgresQueryViewStore{recordAudit: recordAudit, pool: pool, fence: tenancy.NewPostgresWriterFence(pool), maxBytes: maxBytes, now: time.Now}
}

func (s *PostgresQueryViewStore) inTenant(ctx context.Context, tenant, owner string, fn func(context.Context, tenancy.Scope) error) error {
	if err := queryViewScope(tenant, owner); err != nil {
		return err
	}
	if s == nil || s.pool == nil {
		return errors.New("saved flow query storage is unavailable")
	}
	return tenancy.InTenant(tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(tenant))), s.pool, fn)
}

const queryViewColumns = `v.id::text,v.tenant_id::text,v.owner_id,v.definition,v.version,v.created_at,v.updated_at,COALESCE(p.favorite,false),p.last_opened_at`
const queryViewJoin = ` FROM flow_query_views v LEFT JOIN flow_query_view_preferences p ON p.tenant_id=v.tenant_id AND p.view_id=v.id AND p.owner_id=$2 `
const queryViewVisibleSQL = `v.tenant_id=$1::uuid AND (v.owner_id=$2 OR v.visibility='tenant')`

func scanQueryView(row queryFilterScanner) (SavedQueryView, error) {
	var item SavedQueryView
	var definition []byte
	var version int64
	if err := row.Scan(&item.ID, &item.TenantID, &item.OwnerID, &definition, &version, &item.CreatedAt, &item.UpdatedAt, &item.Favorite, &item.LastOpenedAt); err != nil {
		return SavedQueryView{}, queryViewStorageError(err)
	}
	if version < 1 || len(definition) > 2*MaxPlanGrammarBytes {
		return SavedQueryView{}, ErrQueryViewBudget
	}
	decoder := json.NewDecoder(bytes.NewReader(definition))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&item.Definition); err != nil {
		return SavedQueryView{}, errors.New("stored flow query is invalid")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return SavedQueryView{}, errors.New("stored flow query has trailing content")
	}
	normalized, err := NormalizeQueryViewDefinition(item.Definition, time.Now())
	if err != nil {
		return SavedQueryView{}, errors.New("stored flow query is invalid")
	}
	item.Definition = normalized
	item.Version = strconv.FormatInt(version, 10)
	return item, nil
}

func queryViewStorageError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrQueryViewNotFound
	}
	if errors.Is(queryFilterStorageError(err), ErrQueryFilterNotFound) {
		return ErrQueryViewNotFound
	}
	return err
}

func getScopedQueryView(ctx context.Context, sc tenancy.Scope, tenant, owner, id string) (SavedQueryView, error) {
	return scanQueryView(sc.Q.QueryRow(ctx, `SELECT `+queryViewColumns+queryViewJoin+`WHERE `+queryViewVisibleSQL+` AND v.id=$3::uuid`, tenant, owner, id))
}

func (s *PostgresQueryViewStore) GetQueryView(ctx context.Context, tenant, owner, id string) (SavedQueryView, error) {
	var result SavedQueryView
	err := s.inTenant(ctx, tenant, owner, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = getScopedQueryView(ctx, sc, tenant, owner, id)
		return err
	})
	return result, queryViewStorageError(err)
}

func queryViewLock(ctx context.Context, sc tenancy.Scope, tenant string) error {
	// The same order as saved filters; views cannot validate a disappearing
	// reference while a concurrent filter mutation holds the tenant lock.
	_, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('probectl.flow_query_filters:' || $1::text,0))`, tenant)
	return err
}

func (s *PostgresQueryViewStore) SaveQueryView(ctx context.Context, tenant, owner string, input SaveQueryView) (SavedQueryView, error) {
	if err := queryViewScope(tenant, owner); err != nil {
		return SavedQueryView{}, err
	}
	input, err := NormalizeSaveQueryView(input, s.now())
	if err != nil {
		return SavedQueryView{}, err
	}
	var result SavedQueryView
	err = tenancy.FencedWrite(ctx, s.fence, []string{tenant}, func(tenant string) string { return tenant }, errors.New("saved flow query tenant is required"), func(ctx context.Context) error {
		return s.inTenant(ctx, tenant, owner, func(ctx context.Context, sc tenancy.Scope) error {
			if err := queryViewLock(ctx, sc, tenant); err != nil {
				return err
			}
			previous := SavedQueryView{}
			revision := int64(0)
			if input.ID != "" {
				var err error
				previous, err = getScopedQueryView(ctx, sc, tenant, owner, input.ID)
				if err != nil {
					return err
				}
				if previous.OwnerID != owner {
					return ErrQueryViewNotFound
				}
				if previous.Version != input.Version {
					return ErrQueryViewConflict
				}
				revision, err = QueryViewVersion(previous.Version)
				if err != nil {
					return err
				}
			}
			if revision == math.MaxInt64 {
				return ErrQueryViewConflict
			}
			if _, err := ResolveQueryFilters(ctx, tenant, input.Definition.Plan.Filter, scopedQueryFilterReader{sc}, ""); err != nil {
				return err
			}
			encoded, err := json.Marshal(input.Definition)
			if err != nil {
				return err
			}
			var definitionBytes, used int64
			if err := sc.Q.QueryRow(ctx, `SELECT octet_length($1::jsonb::text)`, string(encoded)).Scan(&definitionBytes); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT COALESCE(sum(octet_length(definition::text)+octet_length(owner_id)+128),0)::bigint FROM flow_query_views WHERE tenant_id=$1::uuid AND ($2='' OR id::text<>$2)`, tenant, input.ID).Scan(&used); err != nil {
				return err
			}
			if used+definitionBytes+int64(len(owner)+128) > int64(s.maxBytes) {
				return ErrQueryViewBudget
			}
			now := s.now().UTC()
			id := input.ID
			created := previous.CreatedAt
			if id == "" {
				id, err = crypto.UUIDv4()
				if err != nil {
					return err
				}
				created = now
			}
			result = SavedQueryView{ID: id, TenantID: tenant, OwnerID: owner, Version: strconv.FormatInt(revision+1, 10), Definition: input.Definition, CreatedAt: created, UpdatedAt: now, Favorite: previous.Favorite, LastOpenedAt: previous.LastOpenedAt}
			if input.ID == "" {
				_, err = sc.Q.Exec(ctx, `INSERT INTO flow_query_views(tenant_id,id,owner_id,name,visibility,definition,version,created_at,updated_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6::jsonb,1,$7,$7)`, tenant, id, owner, input.Definition.Name, input.Definition.Visibility, string(encoded), now)
			} else {
				command, e := sc.Q.Exec(ctx, `UPDATE flow_query_views SET name=$4,visibility=$5,definition=$6::jsonb,version=version+1,updated_at=$7 WHERE tenant_id=$1::uuid AND id=$2::uuid AND owner_id=$3 AND version=$8`, tenant, id, owner, input.Definition.Name, input.Definition.Visibility, string(encoded), now, revision)
				err = e
				if err == nil && command.RowsAffected() != 1 {
					return ErrQueryViewConflict
				}
			}
			if err != nil {
				return err
			}
			action := "flow.view.create"
			if input.ID != "" {
				action = "flow.view.update"
			}
			err = recordQueryConfig(ctx, sc, s.recordAudit, owner, action, id, map[string]any{"version": result.Version, "definition_hash": fmt.Sprintf("%x", crypto.Hash(encoded)), "visibility": input.Definition.Visibility})
			return err
		})
	})
	if err != nil {
		return SavedQueryView{}, queryViewStorageError(err)
	}
	return cloneQueryView(result)
}

func (s *PostgresQueryViewStore) ListQueryViews(ctx context.Context, tenant, owner string, input QueryViewList) (QueryViewPage, error) {
	input, err := NormalizeQueryViewList(input)
	if err != nil {
		return QueryViewPage{}, err
	}
	page := QueryViewPage{Items: []SavedQueryView{}}
	err = s.inTenant(ctx, tenant, owner, func(ctx context.Context, sc tenancy.Scope) error {
		order := "v.name COLLATE \"C\""
		direction := ">"
		descending := ""
		if input.Sort == "created_at" {
			order = "v.created_at"
			direction = "<"
			descending = " DESC"
		}
		if input.Sort == "updated_at" {
			order = "v.updated_at"
			direction = "<"
			descending = " DESC"
		}
		var afterValue any
		afterID := ""
		if input.After != "" {
			after, err := getScopedQueryView(ctx, sc, tenant, owner, input.After)
			if err != nil {
				return err
			}
			afterID = after.ID
			switch input.Sort {
			case "name":
				afterValue = after.Definition.Name
			case "created_at":
				afterValue = after.CreatedAt
			case "updated_at":
				afterValue = after.UpdatedAt
			}
			if input.Tab == "recents" {
				afterValue = after.LastOpenedAt
				if after.LastOpenedAt == nil {
					return ErrQueryViewNotFound
				}
			}
		}
		extra := ""
		if input.Tab == "favorites" {
			extra = " AND COALESCE(p.favorite,false)"
		}
		if input.Tab == "recents" {
			extra = " AND p.last_opened_at IS NOT NULL"
			order = "p.last_opened_at"
			direction = "<"
			descending = " DESC"
		}
		args := []any{tenant, owner, input.Visibility, input.Owner, input.Search, input.Label}
		where := queryViewVisibleSQL + ` AND ($3='' OR v.visibility=$3) AND ($4='' OR v.owner_id=$4) AND ($5='' OR position(lower($5) in lower(v.name))>0) AND ($6='' OR v.definition->'labels' @> jsonb_build_array($6::text))` + extra
		if afterID != "" {
			args = append(args, afterValue, afterID)
			where += " AND (" + order + direction + "$7 OR (" + order + "=$7 AND v.id>$8::uuid))"
		}
		args = append(args, input.Limit+1)
		query := `SELECT ` + queryViewColumns + queryViewJoin + `WHERE ` + where + ` ORDER BY ` + order + descending + `,v.id LIMIT $` + strconv.Itoa(len(args))
		rows, err := sc.Q.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		used := 0
		for rows.Next() {
			item, err := scanQueryView(rows)
			if err != nil {
				return err
			}
			more, err := appendQueryViewPage(&page, item, input.Limit, &used)
			if err != nil {
				return err
			}
			if more {
				break
			}
		}
		return rows.Err()
	})
	return page, queryViewStorageError(err)
}

func (s *PostgresQueryViewStore) DeleteQueryView(ctx context.Context, tenant, owner, id, version string) error {
	if err := queryViewScope(tenant, owner); err != nil {
		return err
	}
	return tenancy.FencedWrite(ctx, s.fence, []string{tenant}, func(t string) string { return t }, ErrQueryViewNotFound, func(ctx context.Context) error {
		return s.inTenant(ctx, tenant, owner, func(ctx context.Context, sc tenancy.Scope) error {
			if err := queryViewLock(ctx, sc, tenant); err != nil {
				return err
			}
			item, err := getScopedQueryView(ctx, sc, tenant, owner, id)
			if err != nil {
				return err
			}
			if item.OwnerID != owner {
				return ErrQueryViewNotFound
			}
			revision, err := QueryViewVersion(version)
			if err != nil {
				return err
			}
			if item.Version != version {
				return ErrQueryViewConflict
			}
			result, err := sc.Q.Exec(ctx, `DELETE FROM flow_query_views WHERE tenant_id=$1::uuid AND id=$2::uuid AND owner_id=$3 AND version=$4`, tenant, id, owner, revision)
			if err != nil {
				return err
			}
			if result.RowsAffected() != 1 {
				return ErrQueryViewConflict
			}
			err = recordQueryConfig(ctx, sc, s.recordAudit, owner, "flow.view.delete", id, map[string]any{"version": version})
			return err
		})
	})
}

func (s *PostgresQueryViewStore) SetQueryViewPreference(ctx context.Context, tenant, owner, id string, favorite *bool, opened bool) error {
	if err := queryViewScope(tenant, owner); err != nil {
		return err
	}
	return tenancy.FencedWrite(ctx, s.fence, []string{tenant}, func(t string) string { return t }, ErrQueryViewNotFound, func(ctx context.Context) error {
		return s.inTenant(ctx, tenant, owner, func(ctx context.Context, sc tenancy.Scope) error {
			if err := queryViewLock(ctx, sc, tenant); err != nil {
				return err
			}
			if _, err := getScopedQueryView(ctx, sc, tenant, owner, id); err != nil {
				return err
			}
			var used int64
			if err := sc.Q.QueryRow(ctx, `SELECT COALESCE(sum(octet_length(owner_id)+128),0)::bigint FROM flow_query_view_preferences WHERE tenant_id=$1::uuid`, tenant).Scan(&used); err != nil {
				return err
			}
			var exists bool
			if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_query_view_preferences WHERE tenant_id=$1::uuid AND owner_id=$2 AND view_id=$3::uuid)`, tenant, owner, id).Scan(&exists); err != nil {
				return err
			}
			if !exists && used+int64(len(owner)+128) > int64(s.maxBytes) {
				return ErrQueryViewBudget
			}
			var at *time.Time
			if opened {
				now := s.now().UTC()
				at = &now
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO flow_query_view_preferences(tenant_id,owner_id,view_id,favorite,last_opened_at) VALUES($1::uuid,$2,$3::uuid,COALESCE($4::boolean,false),$5) ON CONFLICT(tenant_id,owner_id,view_id) DO UPDATE SET favorite=COALESCE($4::boolean,flow_query_view_preferences.favorite),last_opened_at=COALESCE($5,flow_query_view_preferences.last_opened_at)`, tenant, owner, id, favorite, at)
			if err != nil {
				return err
			}
			err = recordQueryConfig(ctx, sc, s.recordAudit, owner, "flow.view.preference", id, map[string]any{"opened": opened, "favorite_changed": favorite != nil})
			return err
		})
	})
}

var _ QueryViewStore = (*PostgresQueryViewStore)(nil)
var _ QueryViewStore = (*MemoryQueryViewStore)(nil)
