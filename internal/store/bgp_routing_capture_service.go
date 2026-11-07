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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPRoutingCaptureReference identifies a first processing-time observation.
// It contains no route or source grant. Outward readers independently resolve
// its immutable payload under current tenant/actor/context authorization.
type BGPRoutingCaptureReference struct {
	Key        [32]byte
	CapturedAt time.Time
}

// BGPRoutingFlowCaptures is an ingestion-only adapter around existing routed
// Postgres state. The caller derives Key from the verified raw observation,
// before enrichment or time clamping; no packet supplies a canonical context.
type BGPRoutingFlowCaptures struct{ pool *pgxpool.Pool }

func NewBGPRoutingFlowCaptures(pool *pgxpool.Pool) *BGPRoutingFlowCaptures {
	return &BGPRoutingFlowCaptures{pool: pool}
}

func (service *BGPRoutingFlowCaptures) Capture(ctx context.Context, key [32]byte, input BGPRoutingFlowInput, budget BGPRoutingBudget) (BGPRoutingCaptureReference, error) {
	if err := ctx.Err(); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if canonical, err := validRegistryUUID(tenant.String()); !ok || err != nil || canonical != tenant.String() {
		return BGPRoutingCaptureReference{}, entity.ErrScopeMismatch
	}
	if key == ([32]byte{}) || budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || budget.StateBytes <= 0 {
		return BGPRoutingCaptureReference{}, ErrBGPRoutingBudget
	}
	if service == nil || service.pool == nil {
		return BGPRoutingCaptureReference{}, ErrBGPRoutingSourceUnavailable
	}
	ctx = tenancy.WithSiloTableLock(ctx)
	var sourceGeneration int64
	var previous routingCaptureReceipt
	var exists bool
	err := tenancy.InTenant(ctx, service.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		sourceGeneration, err = flowsnapshot.SourceGenerationInScope(ctx, sc)
		if err == nil {
			previous, exists, err = loadRoutingCaptureReceiptInScope(ctx, sc, key)
		}
		return err
	})
	if err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	if exists {
		return routingCaptureReference(previous), nil
	}
	objects, err := service.captureCurrentFlow(ctx, input, budget)
	if err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	var stored routingCaptureReceipt
	err = tenancy.InTenant(ctx, service.pool, func(ctx context.Context, sc tenancy.Scope) error {
		// Epoch preparation performs its ordinary fenced INSERT before the
		// audit lock. The transaction retains that tenant writer lease through
		// publication, without holding a second pool connection. The original
		// token is checked again under the audit lock by retainRoutingCapture.
		if _, err := flowsnapshot.SourceGenerationInScope(ctx, sc); err != nil {
			return err
		}
		var err error
		stored, err = retainRoutingCaptureInScope(ctx, sc, key, objects, sourceGeneration, budget)
		return err
	})
	if err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	return routingCaptureReference(stored), nil
}

func (service *BGPRoutingFlowCaptures) captureCurrentFlow(ctx context.Context, input BGPRoutingFlowInput, budget BGPRoutingBudget) (*routingCaptureObjects, error) {
	var captured BGPRoutingFlowLookup
	err := tenancy.InTenantReadSnapshot(ctx, service.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		captured, err = (BGPRouting{}).LookupFlowInScope(ctx, sc, input, budget)
		return err
	})
	// An unavailable first lookup is itself immutable. A later retry cannot
	// attach routes that were absent, ambiguous or unattested on first capture.
	if errors.Is(err, ErrBGPRoutingFlowSource) || errors.Is(err, ErrBGPRoutingSourceUnavailable) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	objects, err := freezeRoutingCapture(ctx, captured, budget)
	if err != nil {
		return nil, err
	}
	return &objects, nil
}

func routingCaptureReference(receipt routingCaptureReceipt) BGPRoutingCaptureReference {
	return BGPRoutingCaptureReference{Key: receipt.key, CapturedAt: receipt.capturedAt.UTC()}
}
