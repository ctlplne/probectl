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

func TestRoutingCaptureServiceRequiresTenantBeforeAvailability(t *testing.T) {
	service := NewBGPRoutingFlowCaptures(nil)
	key := routingCaptureHash([]byte("verified raw flow"))
	for _, ctx := range []context.Context{t.Context(), tenancy.WithTenant(t.Context(), tenancy.ID("invalid"))} {
		if got, err := service.Capture(ctx, key, BGPRoutingFlowInput{}, routingViewBudget()); !errors.Is(err, entity.ErrScopeMismatch) || got != (BGPRoutingCaptureReference{}) {
			t.Fatal("unscoped capture reached service availability", err)
		}
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	if got, err := service.Capture(ctx, key, BGPRoutingFlowInput{}, routingViewBudget()); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got != (BGPRoutingCaptureReference{}) {
		t.Fatal("missing capture storage invented a reference", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := service.Capture(canceled, key, BGPRoutingFlowInput{}, routingViewBudget()); !errors.Is(err, context.Canceled) || got != (BGPRoutingCaptureReference{}) {
		t.Fatal("canceled capture returned a partial reference", err)
	}
}
