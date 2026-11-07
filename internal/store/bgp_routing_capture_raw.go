// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type rawRoutingCapture struct {
	key     [32]byte
	witness entity.FlowCaptureWitness
	ref     BGPRoutingCaptureReference
	objects *routingCaptureObjects
}

// StageRaw fixes first-ingestion metadata for the complete admitted raw batch.
// Claimed sender identity is untrusted: any candidate is private and absent
// from terminal readers until exact authenticated evidence finalizes it.
// Missing ownership/source proof seals unavailable. This method never calls
// the authenticated publisher and never creates a positive terminal receipt.
func (service *BGPRoutingFlowCaptures) StageRaw(ctx context.Context, sender string, witnesses []entity.FlowCaptureWitness, budget BGPRoutingBudget) ([]BGPRoutingCaptureReference, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if canonical, err := validRegistryUUID(tenant.String()); !ok || err != nil || canonical != tenant.String() {
		return nil, entity.ErrScopeMismatch
	}
	count := int64(len(witnesses))
	if count == 0 || budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || count > budget.MemoryBytes/4096 || count > budget.WorkUnits/4096 {
		return nil, ErrBGPRoutingBudget
	}
	rows := make([]rawRoutingCapture, len(witnesses))
	for i, witness := range witnesses {
		key, err := service.captureKey(ctx, sender, witness.RawDigest, witness.Input, budget)
		if err != nil {
			return nil, err
		}
		rows[i] = rawRoutingCapture{key: key, witness: witness}
	}
	ctx = tenancy.WithSiloTableLock(ctx)
	var generation int64
	err := tenancy.InTenant(ctx, service.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		generation, err = sourceepoch.SourceGenerationInScope(ctx, sc)
		if err != nil {
			return err
		}
		for i := range rows {
			if previous, exists, err := loadRoutingCaptureReceiptInScope(ctx, sc, rows[i].key); err != nil {
				return err
			} else if exists {
				rows[i].ref = routingCaptureReference(previous)
				continue
			}
			if intent, exists, err := loadRoutingCaptureIntentInScope(ctx, sc, rows[i].key); err != nil {
				return err
			} else if exists {
				rows[i].ref = intent.reference()
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	operation := budget
	operation.MemoryBytes -= count * 512
	operation.WorkUnits -= count * 4096
	err = tenancy.InTenantReadSnapshot(ctx, service.pool, func(ctx context.Context, sc tenancy.Scope) error {
		// Request-local sharing only. No authority survives this snapshot.
		byInput := map[entity.FlowCaptureInput]*routingCaptureObjects{}
		content := map[[32]byte]routingCaptureObject{}
		for i := range rows {
			if rows[i].ref.Key != ([32]byte{}) {
				continue
			}
			input := rows[i].witness.Input
			if objects, found := byInput[input]; found {
				rows[i].objects = objects
				continue
			}
			if err := routingBatchCharge(&operation, 0, 4096); err != nil {
				return err
			}
			objects, err := captureRawRoutingCandidate(ctx, sc, sender, input, operation)
			if err != nil {
				return err
			}
			if objects != nil {
				for _, object := range []*routingCaptureObject{&objects.facts, &objects.clocks} {
					if err := routingBatchCharge(&operation, 0, int64(len(object.payload))*16); err != nil {
						return err
					}
					if shared, exists := content[object.digest]; exists {
						if shared.payload != object.payload {
							return errRoutingCaptureFormat
						}
						*object = shared
					} else {
						if err := routingBatchCharge(&operation, int64(len(object.payload))*16+4096, 0); err != nil {
							return err
						}
						content[object.digest] = *object
					}
				}
			}
			byInput[input], rows[i].objects = objects, objects
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	refs := make([]BGPRoutingCaptureReference, len(rows))
	err = tenancy.InTenant(ctx, service.pool, func(ctx context.Context, sc tenancy.Scope) error {
		// Prepare the normal tenant writer lease before publication locks.
		if _, err := sourceepoch.SourceGenerationInScope(ctx, sc); err != nil {
			return err
		}
		for i := range rows {
			if rows[i].ref.Key != ([32]byte{}) {
				refs[i] = rows[i].ref
				continue
			}
			var err error
			refs[i], err = retainRawRoutingCaptureInScope(ctx, sc, rows[i].key, rows[i].objects, generation, budget)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return refs, nil
}

func captureRawRoutingCandidate(ctx context.Context, sc tenancy.Scope, sender string, input BGPRoutingFlowInput, budget BGPRoutingBudget) (*routingCaptureObjects, error) {
	lookup, err := (BGPRouting{}).LookupFlowInScope(ctx, sc, input, budget)
	if errors.Is(err, ErrBGPRoutingFlowSource) || errors.Is(err, ErrBGPRoutingSourceUnavailable) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if lookup.Owner.AgentID != sender {
		return nil, nil
	}
	objects, err := freezeRoutingCapture(ctx, lookup, budget)
	if err != nil {
		return nil, err
	}
	return &objects, nil
}

func retainRawRoutingCaptureInScope(ctx context.Context, sc tenancy.Scope, key [32]byte, objects *routingCaptureObjects, generation int64, budget BGPRoutingBudget) (BGPRoutingCaptureReference, error) {
	if objects != nil {
		return retainRoutingCaptureIntentInScope(ctx, sc, key, *objects, generation, budget)
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
	if receipt, exists, err := loadRoutingCaptureReceiptInScope(ctx, sc, key); err != nil || exists {
		return routingCaptureReference(receipt), err
	}
	if intent, exists, err := loadRoutingCaptureIntentInScope(ctx, sc, key); err != nil || exists {
		return intent.reference(), err
	}
	receipt, err := retainRoutingCaptureInScope(ctx, sc, key, nil, generation, budget)
	return routingCaptureReference(receipt), err
}
