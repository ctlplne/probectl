// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// NewKubernetesInventoryPruner deletes complete expired generations and
// abandoned uploads. Source assignments remain operator configuration.
func NewKubernetesInventoryPruner(pool *pgxpool.Pool) func(context.Context, string, time.Time) (int64, error) {
	fence := tenancy.NewPostgresWriterFence(pool)
	return func(ctx context.Context, tenant string, cutoff time.Time) (int64, error) {
		bound, exists := tenancy.FromContext(ctx)
		if pool == nil || tenant == "" || cutoff.IsZero() || exists && bound.String() != tenant {
			return 0, ErrKubernetesInventoryAuthority
		}
		ctx = tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(tenant)))
		var deleted int64
		err := fence.WithTenantWrites(ctx, []string{tenant}, func(ctx context.Context) error {
			return tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
				return sc.Q.QueryRow(ctx, `
WITH stale AS (
 SELECT DISTINCT context_id,source_id,generation_id FROM kubernetes_inventory_windows
 WHERE tenant_id=$1 AND valid_until<=$2
), generations AS (
 DELETE FROM kubernetes_inventory_generations g USING stale
 WHERE g.tenant_id=$1 AND (g.context_id,g.source_id,g.id)=(stale.context_id,stale.source_id,stale.generation_id)
 RETURNING 1
), staging AS (
 DELETE FROM kubernetes_inventory_staging WHERE tenant_id=$1 AND expires_at<=transaction_timestamp()
 RETURNING 1
)
SELECT (SELECT count(*) FROM generations)+(SELECT count(*) FROM staging)`, sc.Tenant.String(), cutoff).Scan(&deleted)
			})
		})
		if err != nil {
			return 0, err
		}
		return deleted, nil
	}
}
