// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"sync/atomic"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingTransferPublicationKey struct{}

type routingTransferPublication struct {
	active atomic.Bool
	tenant tenancy.ID
	conn   *pgx.Conn
}

// WithRoutingTransferPublication uses the existing BGP writer and tenant
// audit locks. The archive fence acquires its source and stream locks before
// audit, in the same order as the archive writer. Only the scoped final
// verification and mutation can use these reads on a read-committed backend.
func (BGPRouting) WithRoutingTransferPublication(ctx context.Context, sc tenancy.Scope,
	lockArchive, publish func(context.Context, tenancy.Scope) error) error {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return err
	}
	tx, ok := sc.Q.(pgx.Tx)
	if !ok || lockArchive == nil || publish == nil {
		return errBGPRoutingReadSnapshot
	}
	var tenant, role string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(current_setting('probectl.tenant_id',true),''), current_user`).Scan(&tenant, &role); err != nil {
		return err
	}
	if tenant != sc.Tenant.String() || role != tenancy.AppRole {
		return entity.ErrScopeMismatch
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return err
	}
	if err := lockArchive(ctx, sc); err != nil {
		return err
	}
	if err := tenancy.LockTenantAuditStream(ctx, sc.Q, tenant); err != nil {
		return err
	}
	fence := &routingTransferPublication{tenant: sc.Tenant, conn: tx.Conn()}
	fence.active.Store(true)
	defer fence.active.Store(false)
	// Reuse the existing capture reader's proof that this actual backend
	// holds the audit lock when it rechecks original flow authority.
	ctx = WithReportSourceAuditLock(ctx, sc)
	return publish(context.WithValue(ctx, routingTransferPublicationKey{}, fence), sc)
}

func requireRoutingTransferReadSnapshot(ctx context.Context, sc tenancy.Scope) error {
	fence, publication := ctx.Value(routingTransferPublicationKey{}).(*routingTransferPublication)
	if !publication {
		return requireRoutingReadSnapshot(ctx, sc)
	}
	tenant, bound := tenancy.FromContext(ctx)
	tx, transactional := sc.Q.(pgx.Tx)
	if !bound || !transactional || !fence.active.Load() || tenant != sc.Tenant ||
		tenant != fence.tenant || tx.Conn() != fence.conn {
		return entity.ErrScopeMismatch
	}
	return ctx.Err()
}
