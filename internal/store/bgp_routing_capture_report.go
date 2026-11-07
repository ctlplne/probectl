// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingReportPublicationKey struct{}

// FlowCaptureQueryProjectionsForReportInScope reuses a report's existing tenant
// transaction. Read-only inbox snapshots keep the ordinary snapshot guard.
// Final publication/download may use read committed only while this backend
// holds the actual canonical tenant audit lock: source writes cannot commit
// across the read, and authority committed before a lock wait is freshly read.
func (BGPRouting) FlowCaptureQueryProjectionsForReportInScope(ctx context.Context, sc tenancy.Scope, reads []flowstore.RoutingCaptureRead, budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error) ([]flowstore.RoutingProjection, error) {
	if err := requireRoutingReadSnapshot(ctx, sc); err == nil {
		return readRoutingCaptureQueryBatchInScope(ctx, sc, reads, budget, authorize)
	}
	ctx = context.WithValue(ctx, routingReportPublicationKey{}, sc.Tenant.String())
	return readRoutingCaptureQueryBatchInScope(ctx, sc, reads, budget, authorize)
}

func requireRoutingCaptureReadSnapshot(ctx context.Context, sc tenancy.Scope) error {
	tenant, publication := ctx.Value(routingReportPublicationKey{}).(string)
	if !publication {
		return requireRoutingReadSnapshot(ctx, sc)
	}
	if err := routingCaptureScope(ctx, sc); err != nil {
		return err
	}
	if tenant != sc.Tenant.String() {
		return entity.ErrScopeMismatch
	}
	var held bool
	err := sc.Q.QueryRow(ctx, `WITH tenant_lock AS (
 SELECT hashtextextended('audit:'||$1::text,0) AS key)
 SELECT EXISTS(SELECT 1 FROM pg_locks locks CROSS JOIN tenant_lock
 WHERE locks.locktype='advisory' AND locks.pid=pg_backend_pid()
 AND locks.database=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND locks.classid=((tenant_lock.key >> 32) & 4294967295)::oid
 AND locks.objid=(tenant_lock.key & 4294967295)::oid AND locks.objsubid=1
 AND locks.mode='ExclusiveLock' AND locks.granted)`, tenant).Scan(&held)
	if err != nil {
		return err
	}
	if !held {
		return errBGPRoutingReadSnapshot
	}
	return nil
}
