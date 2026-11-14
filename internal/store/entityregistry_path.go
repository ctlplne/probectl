// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PathTestBinding carries the operator's routing context, normalized
// destination and earliest discovery time from one validated tenant row.
// Older rounds have no proven context; a separate test read must not choose
// the destination because a retarget may occur between those reads.
type PathTestBinding struct {
	Scope      entity.Scope
	Target     string
	AssignedAt time.Time
}

// AssignPathTestContext binds an owned test to a routing context. A valid
// targetless noop gets general metadata context only, never path authority.
// Both compound FKs enforce the tenant at the storage layer; the caller must
// append its audit event in the same transaction.
func (s *EntityRegistry) AssignPathTestContext(ctx context.Context, sc tenancy.Scope, testID, contextID string) error {
	if s == nil || s.pool == nil {
		return ErrEntityRegistryUnavailable
	}
	testID, err := validRegistryUUID(testID)
	if err != nil {
		return err
	}
	contextID, err = validRegistryUUID(contextID)
	if err != nil {
		return err
	}
	var testType, testTarget string
	if err := sc.Q.QueryRow(ctx, `SELECT type,target FROM tests
		WHERE tenant_id=$1 AND id=$2 FOR UPDATE`,
		sc.Tenant.String(), testID).Scan(&testType, &testTarget); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.ErrScopeMismatch
		}
		return err
	}
	pathTarget := path.TargetHost(testTarget)
	withoutPath := testType == "noop" && testTarget == ""
	if !withoutPath && (pathTarget == "" || len(pathTarget) > 1024) {
		return entity.ErrInvalidClaim
	}
	// The path and general test contexts are one explicit operator binding.
	// Serialize on the test row. Preserve equal-context timestamps; a context
	// change removes stale context-specific path/tag children atomically.
	if _, err := sc.Q.Exec(ctx, `DELETE FROM entity_test_contexts
		WHERE tenant_id=$1 AND test_id=$2 AND context_id<>$3`,
		sc.Tenant.String(), testID, contextID); err != nil {
		return err
	}
	if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_test_contexts
		(tenant_id,test_id,context_id) VALUES ($1,$2,$3)
		ON CONFLICT (tenant_id,test_id) DO NOTHING`,
		sc.Tenant.String(), testID, contextID); err != nil {
		return err
	}
	if withoutPath {
		// A metadata-only binding cannot preserve an earlier destination's
		// path authority, including after a type/target change.
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_path_test_contexts
			WHERE tenant_id=$1 AND test_id=$2`, sc.Tenant.String(), testID)
		return err
	}
	_, err = sc.Q.Exec(ctx, `INSERT INTO entity_path_test_contexts
		(tenant_id,test_id,context_id,path_target) VALUES ($1,$2,$3,$4)
		ON CONFLICT (tenant_id,test_id) DO UPDATE SET
		context_id=EXCLUDED.context_id,
		path_target=EXCLUDED.path_target,
		assigned_at=CASE WHEN entity_path_test_contexts.context_id IS DISTINCT FROM EXCLUDED.context_id
		                  OR entity_path_test_contexts.path_target IS DISTINCT FROM EXCLUDED.path_target
		                 THEN clock_timestamp() ELSE entity_path_test_contexts.assigned_at END`,
		sc.Tenant.String(), testID, contextID, pathTarget)
	return err
}

// PathTestContext reads only the context assigned to this tenant's test. An
// unbound test stays unresolved; the target IP or a responding hop cannot
// select a context implicitly.
func (s *EntityRegistry) PathTestContext(ctx context.Context, tenantID, testID string) (entity.Scope, error) {
	binding, err := s.PathTestBinding(ctx, tenantID, testID)
	return binding.Scope, err
}

// PathTestBinding reads the assignment time from the same tenant-scoped row as
// the context. A path observed before this binding cannot inherit its context.
func (s *EntityRegistry) PathTestBinding(ctx context.Context, tenantID, testID string) (PathTestBinding, error) {
	if s == nil || s.pool == nil {
		return PathTestBinding{}, ErrEntityRegistryUnavailable
	}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenantID {
		return PathTestBinding{}, entity.ErrScopeMismatch
	}
	var out PathTestBinding
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = s.PathTestBindingInScope(ctx, sc, testID)
		return err
	})
	return out, err
}

// PathTestBindingInScope preserves the caller's existing RLS snapshot and
// publication locks; it never takes a second pool connection in a writer.
func (s *EntityRegistry) PathTestBindingInScope(ctx context.Context, sc tenancy.Scope, testID string) (PathTestBinding, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant {
		return PathTestBinding{}, entity.ErrScopeMismatch
	}
	if sc.Q == nil {
		return PathTestBinding{}, ErrEntityRegistryUnavailable
	}
	testID, err := validRegistryUUID(testID)
	if err != nil {
		return PathTestBinding{}, err
	}
	var contextID, pathTarget, testTarget string
	var assignedAt time.Time
	err = sc.Q.QueryRow(ctx, `SELECT b.context_id::text,b.path_target,t.target,b.assigned_at
			FROM entity_path_test_contexts b JOIN tests t ON
			(t.tenant_id,t.id)=(b.tenant_id,b.test_id)
			WHERE b.tenant_id=$1 AND b.test_id=$2`, sc.Tenant.String(), testID).Scan(
		&contextID, &pathTarget, &testTarget, &assignedAt)
	if err != nil {
		return PathTestBinding{}, err
	}
	if path.TargetHost(testTarget) != pathTarget {
		// The test was edited after its operator binding. The old context
		// cannot authorize a new destination's path; require a fresh binding.
		return PathTestBinding{}, pgx.ErrNoRows
	}
	if assignedAt.IsZero() {
		return PathTestBinding{}, entity.ErrInvalidClaim
	}
	scope, err := (entity.Scope{TenantID: sc.Tenant.String(), ContextID: contextID}).Normalize()
	if err != nil {
		return PathTestBinding{}, err
	}
	return PathTestBinding{Scope: scope, Target: pathTarget, AssignedAt: assignedAt}, nil
}
