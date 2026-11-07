// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Only the already authenticated evidence writer calls this seam. Raw callers
// may stage private candidates but cannot finalize them. Recheck the intent
// under publication locks even if none existed before the source snapshot: a
// concurrent raw ingestion may already have fixed the earlier clock/content.
func finalizeAuthenticatedRoutingCaptureInScope(ctx context.Context, sc tenancy.Scope, key [32]byte, objects *routingCaptureObjects, generation int64, sender string, input BGPRoutingFlowInput, budget BGPRoutingBudget) (routingCaptureReceipt, error) {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return routingCaptureReceipt{}, err
	}
	if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
		return routingCaptureReceipt{}, err
	}
	if err := sourceepoch.MatchSourceGenerationInScope(ctx, sc, generation); err != nil {
		return routingCaptureReceipt{}, err
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return routingCaptureReceipt{}, err
	}
	if previous, exists, err := loadRoutingCaptureReceiptInScope(ctx, sc, key); err != nil || exists {
		return previous, err
	}
	intent, exists, err := loadRoutingCaptureIntentInScope(ctx, sc, key)
	if err != nil {
		return routingCaptureReceipt{}, err
	}
	if exists {
		objects = nil
		if intent.sourceGeneration == generation {
			objects, err = readRoutingCaptureIntentPayloadInScope(ctx, sc, intent, budget)
			if err != nil {
				return routingCaptureReceipt{}, err
			}
		}
	}
	if objects != nil {
		lookup, err := decodeRoutingCapture(ctx, *objects, budget)
		if err != nil {
			return routingCaptureReceipt{}, err
		}
		current, err := routingCapturePublicationCurrent(ctx, sc, lookup, sender, input, budget)
		if err != nil {
			return routingCaptureReceipt{}, err
		}
		if !current {
			objects = nil
		}
	}
	if exists {
		return retainRoutingCaptureInScope(ctx, sc, key, objects, generation, budget, intent.capturedAt)
	}
	return retainRoutingCaptureInScope(ctx, sc, key, objects, generation, budget)
}

// Reauthorize captured ownership and original routing-source credentials. This
// reads current metadata only; it never substitutes a current RIB/path for the
// private first-ingestion snapshot. The publication transaction retains source
// rows through commit, sharing the existing routing writer lock order.
func routingCapturePublicationCurrent(ctx context.Context, sc tenancy.Scope, lookup BGPRoutingFlowLookup, sender string, input BGPRoutingFlowInput, budget BGPRoutingBudget) (bool, error) {
	if lookup.Owner.TenantID != sc.Tenant.String() || lookup.Owner.AgentID != sender || lookup.Owner.Exporter != input.Exporter.Unmap() || lookup.Owner.Protocol != input.Protocol || lookup.Owner.Domain != input.Domain {
		return false, entity.ErrScopeMismatch
	}
	reader := &InterfaceRoleInputsStore{}
	part := entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.WorkUnits / 8}
	owners, err := reader.ExporterOwnersInScope(ctx, sc, part)
	if err != nil {
		return false, err
	}
	owner, err := routingFlowOwner(sc.Tenant.String(), input.Exporter.Unmap(), owners)
	if errors.Is(err, ErrBGPRoutingFlowSource) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if owner.AgentID != sender || owner.Scope != lookup.Owner.Scope || owner.RouterID != lookup.Owner.RouterID {
		return false, nil
	}
	bindings, err := reader.FlowBindingsInScope(ctx, sc, owner.Scope, part)
	if err != nil {
		return false, err
	}
	binding, err := routingFlowBinding(owner, input, bindings)
	if errors.Is(err, ErrBGPRoutingFlowSource) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if binding.SourceID != lookup.Owner.SourceID {
		return false, nil
	}
	id, err := validRegistryUUID(strings.TrimPrefix(binding.SourceID, "evidence/"))
	if err != nil || !strings.HasPrefix(binding.SourceID, "evidence/") {
		return false, errRoutingCaptureFormat
	}
	var present int
	err = sc.Q.QueryRow(ctx, `SELECT 1 FROM entity_evidence e
 JOIN entities node ON (node.tenant_id,node.context_id,node.id)=(e.tenant_id,e.context_id,e.entity_id)
 AND node.kind='device' `+interfaceRoleAuthorityJoinsSQL()+`
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.id=$3 AND e.agent_id=$4
 AND node.id=$5 AND source.anchor_entity_id=node.id
 AND e.source_kind='flow_exporter' AND e.alias_kind='flow_exporter_id'
 AND e.support_evidence_id IS NULL AND `+currentEntityEvidenceSnapshotSQL()+`
 FOR SHARE OF e,node,source,assignment,sender`, sc.Tenant.String(), owner.ContextID, id, sender, owner.RouterID).Scan(&present)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for lane, side := range []BGPRoutingFlowSide{lookup.Source, lookup.Destination} {
		address := input.Source.Unmap()
		if lane == 1 {
			address = input.Destination.Unmap()
		}
		if side.State == "router_selected" && !side.Route.Prefix.Contains(address) {
			return false, errRoutingCaptureFormat
		}
		if side.Route.Source.RouterID == "" {
			continue
		}
		if _, err := (BGPRouting{}).sourceAuthorityForWriteInScope(ctx, sc, side.Route.Source); err != nil {
			if errors.Is(err, ErrBGPRoutingSourceUnavailable) {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}
