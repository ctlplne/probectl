// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ForRouter narrows already-authorized complete tenant metadata for a peering
// query. Validate the complete catalog first: selecting one router must never
// manufacture unique exporter ownership or hide expired source authority.
// Callers still revalidate current user/source grants and the original full
// snapshot before publication. This operation grants no new access.
func (d *InterfaceRoleQueryData) ForRouter(ctx context.Context, scope entity.Scope, routerID string, now time.Time, maxBytes int64) (*InterfaceRoleQueryData, error) {
	bound, present := tenancy.FromContext(ctx)
	normalized, err := scope.Normalize()
	if !present || err != nil || normalized != scope || bound.String() != scope.TenantID || !validTagProjectionID(routerID) {
		return nil, ErrInterfaceRoleQueryScope
	}
	if err := d.validate(ctx, scope.TenantID, now); err != nil {
		return nil, err
	}
	count := int64(0)
	for _, row := range d.rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if row.Scope == scope && row.RouterID == routerID {
			count++
		}
	}
	if count == 0 {
		return nil, ErrInterfaceRoleQueryScope
	}
	// Admit the temporary selection and the constructor's independent complete
	// projection together. No interface count is truncated into a partial view.
	if maxBytes <= 0 || count > maxBytes/512 {
		return nil, ErrExplorerBudget
	}
	rows := make([]InterfaceRoleProjection, 0, int(count))
	for _, row := range d.rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if row.Scope == scope && row.RouterID == routerID {
			rows = append(rows, row)
		}
	}
	// Keep the original observation clock and validity. A read cannot renew it.
	return NewInterfaceRoleQueryData(ctx, scope.TenantID, d.asOf, rows, maxBytes-count*512)
}
