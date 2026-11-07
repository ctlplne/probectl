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

// ReadFlowCaptureInScope reads the original terminal snapshot, never the
// current RIB. The caller must refresh actor/credential authority in this same
// tenant read snapshot and authorize its captured canonical context. Possession
// of a flow key/clock does not grant source access. Private intents, changed
// ownership/credentials and erased payloads are unavailable.
func (BGPRouting) ReadFlowCaptureInScope(ctx context.Context, sc tenancy.Scope, sender string, witness entity.FlowCaptureWitness, ref BGPRoutingCaptureReference, budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error) (BGPRoutingFlowLookup, error) {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if authorize == nil {
		return BGPRoutingFlowLookup{}, entity.ErrScopeMismatch
	}
	key, err := entity.FlowCaptureKey(sc.Tenant.String(), sender, witness.RawDigest, witness.Input)
	if err != nil || key != ref.Key || ref.CapturedAt.UnixNano() <= 0 {
		return BGPRoutingFlowLookup{}, ErrBGPRoutingSourceUnavailable
	}
	receipt, exists, err := readRoutingCaptureInScope(ctx, sc, key, budget)
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if !exists || receipt.objects == nil || !receipt.capturedAt.Equal(ref.CapturedAt) {
		return BGPRoutingFlowLookup{}, ErrBGPRoutingSourceUnavailable
	}
	lookup, err := decodeRoutingCapture(ctx, *receipt.objects, budget)
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	record, err := NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, lookup.Owner.ContextID)
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if err := authorize(ctx, record); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	current, err := routingCaptureAuthorityCurrent(ctx, sc, lookup, sender, witness.Input, budget, false)
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if !current {
		return BGPRoutingFlowLookup{}, ErrBGPRoutingSourceUnavailable
	}
	return lookup, nil
}
