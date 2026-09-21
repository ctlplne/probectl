// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Permissions reads the RBAC catalog and effective grants. It is tenant-scoped:
// RLS confines role bindings and role permissions to the caller's tenant, so a
// user's effective permissions are always computed within their own tenant (the
// tenant boundary is enforced before RBAC).
type Permissions struct{}

// ForSubject returns the distinct permission grants a subject (user or service
// account) holds via its role bindings, within the scope's tenant. Binding scope
// is security data: flattening it would promote a delegated resource grant to
// the whole tenant.
func (Permissions) ForSubject(ctx context.Context, s tenancy.Scope, subjectType, subjectID string) ([]auth.PermissionGrant, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT DISTINCT rp.permission_key, rb.scope_type, COALESCE(rb.scope_id::text, '')
		 FROM role_bindings rb
		 JOIN role_permissions rp ON rp.role_id = rb.role_id
		 WHERE rb.subject_type = $1 AND rb.subject_id = $2
		 ORDER BY rp.permission_key, rb.scope_type, COALESCE(rb.scope_id::text, '')`, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []auth.PermissionGrant{}
	for rows.Next() {
		var grant auth.PermissionGrant
		if err := rows.Scan(&grant.Permission, &grant.ScopeType, &grant.ScopeID); err != nil {
			return nil, err
		}
		out = append(out, grant)
	}
	return out, rows.Err()
}
