// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// EffectInputsInScope is operation-local membership, never a retained incident
// or reusable grant. Only original authenticated routing or explicit archive
// bindings supply a touched identity. Legacy free-form targets stay unresolved.
func (ChangeEvents) EffectInputsInScope(ctx context.Context, sc tenancy.Scope, id string, memory int64) (change.Event, *IncidentImpactInputs, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return change.Event{}, nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return change.Event{}, nil, err
	}
	original, err := (ChangeEvents{}).OriginalInScope(ctx, sc, id, memory)
	if err != nil {
		return change.Event{}, nil, err
	}
	generation, err := incidentImpactSourceGenerationInScope(ctx, sc)
	if err != nil {
		return change.Event{}, nil, err
	}
	inputs := &IncidentImpactInputs{TenantID: sc.Tenant.String(), StartedAt: original.OccurredAt, LastSeenAt: original.OccurredAt, SourceGeneration: generation, Entities: []IncidentImpactEntity{}, UnresolvedSignalIDs: []string{}, RootUnresolved: true}
	var contextID, entityID string
	switch {
	case original.Routing != nil:
		contextID, entityID = original.Routing.ContextID, original.Routing.RouterID
	case original.Config != nil && original.Config.Binding != nil:
		contextID, entityID = original.Config.Binding.ContextID, original.Config.Binding.DeviceEntityID
	}
	if contextID != "" || entityID != "" {
		for _, id := range []string{contextID, entityID} {
			if canonical, err := validRegistryUUID(id); err != nil || canonical != id {
				return change.Event{}, nil, entity.ErrInvalidClaim
			}
		}
		inputs.Entities = append(inputs.Entities, IncidentImpactEntity{ContextID: contextID, EntityID: entityID, IncidentRoot: true, SignalIDs: []string{}})
		inputs.RootUnresolved = false
	}
	return original, inputs, ctx.Err()
}
