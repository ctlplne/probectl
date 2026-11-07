// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoutingCaptureRepositoryRequiresTenantBeforeStorage(t *testing.T) {
	sc := tenancy.Scope{Tenant: tenancy.ID(routingCaptureTenant)}
	key := routingCaptureHash([]byte("verified flow"))
	for _, ctx := range []context.Context{t.Context(), tenancy.WithTenant(t.Context(), tenancy.ID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))} {
		if got, err := retainRoutingCaptureInScope(ctx, sc, key, nil, 1, routingViewBudget()); !errors.Is(err, entity.ErrScopeMismatch) || got.outcome != "" {
			t.Fatal("foreign routing capture reached storage", err)
		}
		if got, exists, err := readRoutingCaptureInScope(ctx, sc, key, routingViewBudget()); !errors.Is(err, entity.ErrScopeMismatch) || exists || got.outcome != "" {
			t.Fatal("foreign routing capture read reached storage", err)
		}
	}
}
