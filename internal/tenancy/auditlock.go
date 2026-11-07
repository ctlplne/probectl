// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import "context"

// LockTenantAuditStream acquires the canonical transaction-scoped tenant audit
// lock. Keeping its key here lets storage and audit share the same lock order
// without a storage-to-audit implementation dependency.
func LockTenantAuditStream(ctx context.Context, q Querier, tenantID string) error {
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('audit:'||$1::text, 0))`, tenantID)
	return err
}
