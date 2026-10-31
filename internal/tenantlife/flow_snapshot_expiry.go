// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// SweepFlowSnapshotExpiry is separate from daily source retention: a short
// cache lifetime must also release its quota promptly. Registry pagination and
// a five-second per-tenant budget bound each visit; no telemetry is read via
// the provider role. The destructive helper requires its standing audit intent.
func (e *Engine) SweepFlowSnapshotExpiry(ctx context.Context) error {
	if e.pool == nil {
		return nil
	}
	var lifecycle any = e.flowSnapshots
	if lifecycle == nil {
		lifecycle = flowsnapshot.NewLifecycle(e.pool, e.objects, tenancy.NewPostgresWriterFence(e.pool))
	}
	maintenance, ok := lifecycle.(flowsnapshot.Maintainer)
	if !ok {
		return errors.New("tenantlife: result-cache expiry maintenance unavailable")
	}
	after := ""
	var failures []error
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		var tenants []string
		err := tenancy.InProvider(ctx, e.pool, func(ctx context.Context, q tenancy.Querier) error {
			rows, err := q.Query(ctx, `SELECT id::text FROM public.tenants WHERE status IN ('active','suspended') AND audit_write_fenced_at IS NULL AND id::text>$1 ORDER BY id LIMIT 1000`, after)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var tenant string
				if err := rows.Scan(&tenant); err != nil {
					return err
				}
				tenants = append(tenants, tenant)
			}
			return rows.Err()
		})
		if err != nil {
			return errors.Join(append(failures, err)...)
		}
		if len(tenants) == 0 {
			break
		}
		for _, tenant := range tenants {
			visit, cancel := context.WithTimeout(ctx, 5*time.Second)
			work, err := maintenance.Reclaimable(visit, tenant)
			if err == nil && work {
				err = e.sweepFlowSnapshotRetention(visit, retentionSweepPolicy{tenant: tenant})
			}
			cancel()
			if err != nil {
				failures = append(failures, fmt.Errorf("tenant %s snapshot expiry: %w", tenant, err))
			}
		}
		after = tenants[len(tenants)-1]
	}
	return errors.Join(failures...)
}

func (e *Engine) RunFlowSnapshotExpiry(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := e.SweepFlowSnapshotExpiry(ctx); err != nil {
			e.log.Warn("flow snapshot expiry maintenance failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
