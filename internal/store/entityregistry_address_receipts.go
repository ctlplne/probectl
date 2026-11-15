// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// CheckCurrentAddressClaims rechecks the exact retained receipts in an already
// scoped resolution. A newer poll need not have the same receipt ID, but cannot
// make an expired, deleted, revoked or rebound original current again. Callers
// independently resolve today's complete candidate set to detect conflicts.
func (s *EntityRegistry) CheckCurrentAddressClaims(ctx context.Context, raw entity.Scope, claims []entity.Claim, memoryBytes int64) error {
	want, err := s.scope(ctx, raw)
	if err != nil {
		return err
	}
	if memoryBytes <= 0 || int64(len(claims)) > memoryBytes/8192 {
		return entity.ErrInvalidPage
	}
	ids := make([]string, 0, len(claims))
	seen := make(map[string]bool, len(claims))
	for _, claim := range claims {
		if claim.Scope != want || claim.Alias.Kind != entity.AddressAlias {
			return entity.ErrScopeMismatch
		}
		if _, err := entity.Resolve(want, claim.Alias, []entity.Claim{claim}); err != nil {
			return err
		}
		if !seen[claim.EvidenceID] {
			ids = append(ids, claim.EvidenceID)
			seen[claim.EvidenceID] = true
		}
	}
	if len(ids) == 0 {
		return ctx.Err()
	}
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence e
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.alias_kind='address'
 AND e.id=ANY($3::uuid[]) AND `+currentEntityEvidenceSnapshotSQL(false), want.TenantID, want.ContextID, ids).Scan(&count)
		if err != nil {
			return err
		}
		if count != len(ids) {
			return ErrEntityRegistryUnavailable
		}
		return ctx.Err()
	})
}
