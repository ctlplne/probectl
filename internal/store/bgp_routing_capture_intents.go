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

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingCaptureIntent struct {
	key              [32]byte
	capturedAt       time.Time
	sourceGeneration int64
}

func (intent routingCaptureIntent) reference() BGPRoutingCaptureReference {
	return BGPRoutingCaptureReference{Key: intent.key, CapturedAt: intent.capturedAt.UTC()}
}

func loadRoutingCaptureIntentInScope(ctx context.Context, sc tenancy.Scope, key [32]byte) (routingCaptureIntent, bool, error) {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return routingCaptureIntent{}, false, err
	}
	intent := routingCaptureIntent{key: key}
	var nanos int64
	err := sc.Q.QueryRow(ctx, `SELECT captured_at_unix_nanos,source_generation FROM bgp_flow_capture_intents WHERE tenant_id=$1 AND flow_key=$2`, sc.Tenant.String(), key[:]).Scan(&nanos, &intent.sourceGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return routingCaptureIntent{}, false, nil
	}
	if err != nil {
		return routingCaptureIntent{}, false, err
	}
	if nanos <= 0 || intent.sourceGeneration < 0 {
		return routingCaptureIntent{}, false, errRoutingCaptureFormat
	}
	intent.capturedAt = time.Unix(0, nanos).UTC()
	return intent, true, nil
}

// The caller holds the existing tenant audit/state locks. Each immutable
// object is byte-admitted before fetching, then the complete pair is decoded
// and hash/scope checked. A missing erased link is a tombstone, never an excuse
// to look up the current RIB or recreate the old candidate.
func readRoutingCaptureIntentPayloadInScope(ctx context.Context, sc tenancy.Scope, intent routingCaptureIntent, budget BGPRoutingBudget) (*routingCaptureObjects, error) {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return nil, err
	}
	var facts, clocks []byte
	err := sc.Q.QueryRow(ctx, `SELECT facts_digest,clocks_digest FROM bgp_flow_capture_intent_payloads WHERE tenant_id=$1 AND flow_key=$2`, sc.Tenant.String(), intent.key[:]).Scan(&facts, &clocks)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(facts) != 32 || len(clocks) != 32 {
		return nil, errRoutingCaptureFormat
	}
	objects := &routingCaptureObjects{capturedAt: intent.capturedAt}
	for i, item := range []struct {
		digest []byte
		kind   string
	}{{facts, "routing_facts"}, {clocks, "routing_clocks"}} {
		object, err := readRoutingCaptureObjectInScope(ctx, sc, item.digest, item.kind, budget)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			objects.facts = object
		} else {
			objects.clocks = object
		}
	}
	if _, err := decodeRoutingCapture(ctx, *objects, budget); err != nil {
		return nil, err
	}
	return objects, nil
}

// An intent is a private candidate, never a terminal receipt. Only a later
// exact authenticated witness may publish it. Existing terminal outcomes and
// intent tombstones win before source content can be inserted or refilled.
// The caller owns the ordinary routed, fenced tenant transaction.
func retainRoutingCaptureIntentInScope(ctx context.Context, sc tenancy.Scope, key [32]byte, objects routingCaptureObjects, generation int64, budget BGPRoutingBudget) (BGPRoutingCaptureReference, error) {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	if key == ([32]byte{}) || objects.capturedAt.UnixNano() <= 0 || budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || budget.StateBytes <= 0 {
		return BGPRoutingCaptureReference{}, ErrBGPRoutingBudget
	}
	// Prepare the ordinary tenant writer lease before the audit lock, even
	// when returning an existing private first clock. Offboarding cannot turn
	// this operation into a metadata-only bypass of its write fence.
	if _, err := sourceepoch.SourceGenerationInScope(ctx, sc); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	if err := sourceepoch.MatchSourceGenerationInScope(ctx, sc, generation); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	if previous, exists, err := loadRoutingCaptureReceiptInScope(ctx, sc, key); err != nil || exists {
		return routingCaptureReference(previous), err
	}
	if intent, exists, err := loadRoutingCaptureIntentInScope(ctx, sc, key); err != nil || exists {
		return intent.reference(), err
	}
	if _, err := decodeRoutingCapture(ctx, objects, budget); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	if err := admitRetainedRoutingCapture(ctx, sc, &objects, budget); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_intents(tenant_id,flow_key,source_generation,captured_at_unix_nanos) VALUES($1,$2,$3,$4)`, sc.Tenant.String(), key[:], generation, objects.capturedAt.UnixNano()); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	if err := insertRoutingCaptureObjects(ctx, sc, objects); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_intent_payloads(tenant_id,flow_key,facts_digest,clocks_digest) VALUES($1,$2,$3,$4)`, sc.Tenant.String(), key[:], objects.facts.digest[:], objects.clocks.digest[:]); err != nil {
		return BGPRoutingCaptureReference{}, err
	}
	return (routingCaptureIntent{key: key, capturedAt: objects.capturedAt, sourceGeneration: generation}).reference(), nil
}
