// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// readFlowCaptureInScope reads the original terminal snapshot, never the
// current RIB. The caller must refresh actor/credential authority in this same
// tenant read snapshot and authorize its captured canonical context. Possession
// of a flow key/clock does not grant source access. Private intents, changed
// ownership/credentials and erased payloads are unavailable.
func (BGPRouting) readFlowCaptureInScope(ctx context.Context, sc tenancy.Scope, sender string, witness entity.FlowCaptureWitness, ref BGPRoutingCaptureReference, budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error) (BGPRoutingFlowLookup, error) {
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
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	// Authorize a bounded canonical context header before fetching/admitting
	// payload bytes. A denied reader must not discover retained payload sizes
	// through resource-admission or decoding errors.
	var contextID string
	err = sc.Q.QueryRow(ctx, `SELECT COALESCE(left(facts.searchable_body#>>'{data,Owner,context_id}',37),'')
 FROM bgp_flow_capture_receipts receipt
 JOIN bgp_flow_capture_payloads links ON (links.tenant_id,links.flow_key)=(receipt.tenant_id,receipt.flow_key)
 JOIN bgp_flow_capture_objects facts ON (facts.tenant_id,facts.digest,facts.kind)=(links.tenant_id,links.facts_digest,'routing_facts')
 WHERE receipt.tenant_id=$1 AND receipt.flow_key=$2 AND receipt.captured_at_unix_nanos=$3
 AND receipt.outcome='captured'`, sc.Tenant.String(), key[:], ref.CapturedAt.UnixNano()).Scan(&contextID)
	if errors.Is(err, pgx.ErrNoRows) {
		return BGPRoutingFlowLookup{}, ErrBGPRoutingSourceUnavailable
	}
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if canonical, err := validRegistryUUID(contextID); err != nil || canonical != contextID {
		return BGPRoutingFlowLookup{}, ErrBGPRoutingSourceUnavailable
	}
	record, err := NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, contextID)
	if err != nil {
		return BGPRoutingFlowLookup{}, err
	}
	if err := authorize(ctx, record); err != nil {
		return BGPRoutingFlowLookup{}, err
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
	if lookup.Owner.ContextID != contextID {
		return BGPRoutingFlowLookup{}, entity.ErrScopeMismatch
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
