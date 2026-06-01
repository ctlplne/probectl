package store

import (
	"context"

	"github.com/imfeelingtheagi/netctl/internal/tenancy"
)

// Permissions reads the RBAC catalog and effective grants. It is tenant-scoped:
// RLS confines role bindings and role permissions to the caller's tenant, so a
// user's effective permissions are always computed within their own tenant (the
// tenant boundary is enforced before RBAC).
type Permissions struct{}

// ForSubject returns the distinct permission keys a subject (user or service
// account) holds via its role bindings, within the scope's tenant.
func (Permissions) ForSubject(ctx context.Context, s tenancy.Scope, subjectType, subjectID string) ([]string, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT DISTINCT rp.permission_key
		 FROM role_bindings rb
		 JOIN role_permissions rp ON rp.role_id = rb.role_id
		 WHERE rb.subject_type = $1 AND rb.subject_id = $2
		 ORDER BY rp.permission_key`, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}
