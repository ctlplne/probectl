// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"strconv"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// QueryViewAccess is current visibility metadata, never query configuration or
// a grant to read its captured source data. Frozen readers separately recheck
// their current credentials and every captured source/context permission.
type QueryViewAccess struct {
	ID, TenantID, OwnerID, Visibility, Version string
}

// QueryViewAccessStore permits a current visibility check without decoding a
// changed definition or replacing any frozen values or input versions.
type QueryViewAccessStore interface {
	GetQueryViewAccess(context.Context, string, string, string) (QueryViewAccess, error)
}

func queryViewAccessScope(ctx context.Context, tenant, owner, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || id == "" {
		return ErrQueryViewNotFound
	}
	if err := queryViewScope(tenant, owner); err != nil {
		return ErrQueryViewNotFound
	}
	return nil
}

func validateQueryViewAccess(item QueryViewAccess, tenant, owner string) (QueryViewAccess, error) {
	if item.ID == "" || item.TenantID != tenant || item.OwnerID == "" || item.Visibility != "private" && item.Visibility != "tenant" {
		return QueryViewAccess{}, ErrQueryViewNotFound
	}
	if item.OwnerID != owner && item.Visibility != "tenant" {
		return QueryViewAccess{}, ErrQueryViewNotFound
	}
	if _, err := QueryViewVersion(item.Version); err != nil {
		return QueryViewAccess{}, ErrQueryViewNotFound
	}
	return item, nil
}

func (s *MemoryQueryViewStore) GetQueryViewAccess(ctx context.Context, tenant, owner, id string) (QueryViewAccess, error) {
	if err := queryViewAccessScope(ctx, tenant, owner, id); err != nil {
		return QueryViewAccess{}, err
	}
	if s == nil {
		return QueryViewAccess{}, ErrQueryViewNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.byTenant[tenant][id]
	if !ok || item.ID != id {
		return QueryViewAccess{}, ErrQueryViewNotFound
	}
	return validateQueryViewAccess(QueryViewAccess{ID: item.ID, TenantID: item.TenantID, OwnerID: item.OwnerID, Visibility: item.Definition.Visibility, Version: item.Version}, tenant, owner)
}

func (s *PostgresQueryViewStore) GetQueryViewAccess(ctx context.Context, tenant, owner, id string) (QueryViewAccess, error) {
	if err := queryViewAccessScope(ctx, tenant, owner, id); err != nil {
		return QueryViewAccess{}, err
	}
	var item QueryViewAccess
	var version int64
	err := s.inTenant(ctx, tenant, owner, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT id::text,tenant_id::text,owner_id,visibility,version FROM flow_query_views WHERE tenant_id=$1::uuid AND (owner_id=$2 OR visibility='tenant') AND id=$3::uuid`, tenant, owner, id).Scan(&item.ID, &item.TenantID, &item.OwnerID, &item.Visibility, &version)
	})
	if err != nil {
		return QueryViewAccess{}, queryViewStorageError(err)
	}
	item.Version = strconv.FormatInt(version, 10)
	return validateQueryViewAccess(item, tenant, owner)
}

var (
	_ QueryViewAccessStore = (*MemoryQueryViewStore)(nil)
	_ QueryViewAccessStore = (*PostgresQueryViewStore)(nil)
)
