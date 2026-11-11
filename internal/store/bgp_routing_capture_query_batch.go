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

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingQueryCaptureHeader struct {
	contextID string
	clock     int64
	objects   [64]byte
}

type routingQueryCaptureCache struct {
	lookup     BGPRoutingFlowLookup
	projection flowstore.RoutingProjection
	current    bool
}

// FlowCaptureQueryProjectionsInScope requires the caller's current actor
// authorizer and an existing tenant read snapshot. Keys never grant access.
func (BGPRouting) FlowCaptureQueryProjectionsInScope(ctx context.Context, sc tenancy.Scope, reads []flowstore.RoutingCaptureRead, budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error) ([]flowstore.RoutingProjection, error) {
	return readRoutingCaptureQueryBatchInScope(ctx, sc, reads, budget, authorize)
}

// This cache is born and discarded inside one existing tenant read snapshot.
// Header authorization precedes all payload admission. Every original tuple,
// key and clock is checked separately; immutable shared content does not grant
// another flow, tenant, context or subsequent request any authority.
func readRoutingCaptureQueryBatchInScope(ctx context.Context, sc tenancy.Scope, reads []flowstore.RoutingCaptureRead, budget BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error, peering ...BGPPeeringCaptureTarget) ([]flowstore.RoutingProjection, error) {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return nil, err
	}
	if authorize == nil {
		return nil, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return nil, err
	}
	if len(peering) > 1 {
		return nil, entity.ErrScopeMismatch
	}
	preauthorized := ""
	if len(peering) == 1 {
		if err := validatePeeringCaptureTarget(ctx, sc, peering[0]); err != nil {
			return nil, err
		}
		record, err := NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, peering[0].ContextID)
		if err != nil {
			return nil, err
		}
		// Empty selections and tiny budgets cannot bypass current context access.
		if err := authorize(ctx, record); err != nil {
			return nil, err
		}
		preauthorized = record.ContextID
	}
	keys, err := routingQueryCaptureKeys(ctx, sc, reads, &budget)
	if err != nil {
		return nil, err
	}
	headers, err := loadRoutingQueryCaptureHeaders(ctx, sc, keys, peering...)
	if err != nil {
		return nil, err
	}
	authorized := map[string]bool{}
	if preauthorized != "" {
		authorized[preauthorized] = true
	}
	authorizeOnce := func(ctx context.Context, record entity.ContextRecord) error {
		if record.TenantID != sc.Tenant.String() {
			return entity.ErrScopeMismatch
		}
		if authorized[record.ContextID] {
			return nil
		}
		if err := authorize(ctx, record); err != nil {
			return err
		}
		authorized[record.ContextID] = true
		return nil
	}
	// Do not fetch an earlier permitted payload before discovering a denied
	// context later in this complete batch.
	for _, read := range reads {
		header, found := headers[read.Ref.Key]
		if !found || header.clock != read.Ref.CapturedAt.UnixNano() || authorized[header.contextID] {
			continue
		}
		record, err := NewEntityRegistry(nil).GetEntityContextInScope(ctx, sc, header.contextID)
		if err != nil {
			return nil, err
		}
		if err := authorizeOnce(ctx, record); err != nil {
			return nil, err
		}
	}
	cache := map[[64]byte]routingQueryCaptureCache{}
	out := make([]flowstore.RoutingProjection, 0, len(reads))
	for _, read := range reads {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, found := headers[read.Ref.Key]
		if !found || header.clock != read.Ref.CapturedAt.UnixNano() {
			continue
		}
		entry, cached := cache[header.objects]
		if !cached {
			entry, err = loadRoutingQueryCaptureCache(ctx, sc, read, header, &budget, authorizeOnce, peering...)
			if err != nil {
				return nil, err
			}
			cache[header.objects] = entry
		}
		if !entry.current {
			continue
		}
		if !routingQueryCaptureMatches(entry.lookup, read, header) {
			return nil, errRoutingCaptureFormat
		}
		projection := entry.projection
		projection.Key, projection.Clock = read.Ref.Key, read.Ref.CapturedAt.UnixNano()
		out = append(out, projection)
	}
	return out, nil
}

func routingQueryCaptureKeys(ctx context.Context, sc tenancy.Scope, reads []flowstore.RoutingCaptureRead, budget *BGPRoutingBudget) ([][]byte, error) {
	if tenant, bound := tenancy.FromContext(ctx); !bound || tenant != sc.Tenant {
		return nil, entity.ErrScopeMismatch
	}
	// Includes input keys, header/seen/cache indexes and retained projections.
	if err := routingCaptureCountCharge(ctx, budget, len(reads), 4096); err != nil {
		return nil, err
	}
	keys := make([][]byte, 0, len(reads))
	seen := make(map[[32]byte]bool, len(reads))
	for _, read := range reads {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if int64(len(read.Sender)) > budget.MemoryBytes/8 {
			return nil, ErrBGPRoutingBudget
		}
		if err := routingBatchCharge(budget, 0, int64(len(read.Sender))*4); err != nil {
			return nil, err
		}
		key, err := entity.FlowCaptureKey(sc.Tenant.String(), read.Sender, read.Witness.RawDigest, read.Witness.Input)
		if err != nil || key != read.Ref.Key || read.Ref.CapturedAt.UnixNano() <= 0 || seen[key] {
			return nil, entity.ErrScopeMismatch
		}
		seen[key] = true
		keys = append(keys, append([]byte(nil), key[:]...))
	}
	return keys, nil
}

func loadRoutingQueryCaptureHeaders(ctx context.Context, sc tenancy.Scope, keys [][]byte, peering ...BGPPeeringCaptureTarget) (map[[32]byte]routingQueryCaptureHeader, error) {
	query := `SELECT receipt.flow_key,receipt.captured_at_unix_nanos,
 links.facts_digest,links.clocks_digest,COALESCE(left(facts.searchable_body#>>'{data,Owner,context_id}',37),'')
 FROM bgp_flow_capture_receipts receipt
 JOIN bgp_flow_capture_payloads links ON (links.tenant_id,links.flow_key)=(receipt.tenant_id,receipt.flow_key)
 JOIN bgp_flow_capture_objects facts ON (facts.tenant_id,facts.digest,facts.kind)=(links.tenant_id,links.facts_digest,'routing_facts')
 JOIN bgp_flow_capture_objects clocks ON (clocks.tenant_id,clocks.digest,clocks.kind)=(links.tenant_id,links.clocks_digest,'routing_clocks')
 WHERE receipt.tenant_id=$1 AND receipt.flow_key=ANY($2::bytea[]) AND receipt.outcome='captured'`
	args := []any{sc.Tenant.String(), keys}
	if len(peering) == 1 {
		query += ` AND facts.searchable_body#>>'{data,Owner,context_id}'=$3
 AND facts.searchable_body#>>'{data,Owner,RouterID}'=$4`
		args = append(args, peering[0].ContextID, peering[0].RouterID)
	}
	rows, err := sc.Q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[[32]byte]routingQueryCaptureHeader, len(keys))
	for rows.Next() {
		var key, facts, clocks []byte
		var header routingQueryCaptureHeader
		if err := rows.Scan(&key, &header.clock, &facts, &clocks, &header.contextID); err != nil {
			return nil, err
		}
		if canonical, err := validRegistryUUID(header.contextID); err != nil || canonical != header.contextID || len(key) != 32 || len(facts) != 32 || len(clocks) != 32 || header.clock <= 0 {
			return nil, errRoutingCaptureFormat
		}
		var id [32]byte
		copy(id[:], key)
		copy(header.objects[:32], facts)
		copy(header.objects[32:], clocks)
		if _, duplicate := out[id]; duplicate || len(out) >= len(keys) {
			return nil, errRoutingCaptureFormat
		}
		out[id] = header
	}
	return out, rows.Err()
}

func loadRoutingQueryCaptureCache(ctx context.Context, sc tenancy.Scope, read flowstore.RoutingCaptureRead, header routingQueryCaptureHeader, budget *BGPRoutingBudget, authorize func(context.Context, entity.ContextRecord) error, peering ...BGPPeeringCaptureTarget) (routingQueryCaptureCache, error) {
	entry := routingQueryCaptureCache{}
	lookup, err := (BGPRouting{}).readFlowCaptureInScope(ctx, sc, read.Sender, read.Witness, read.Ref, *budget, authorize)
	if errors.Is(err, ErrBGPRoutingSourceUnavailable) {
		return entry, nil
	}
	if err != nil {
		return entry, err
	}
	if lookup.Owner.ContextID != header.contextID {
		return entry, entity.ErrScopeMismatch
	}
	if err := chargeRoutingCapture(ctx, lookup, budget); err != nil {
		return entry, err
	}
	projection, err := routingCaptureQueryProjection(ctx, lookup, read.Ref, *budget)
	if err != nil {
		return entry, err
	}
	for name, value := range projection.Fields {
		if err := routingBatchCharge(budget, 256+int64(len(name)+len(value))*12, int64(len(value))*8); err != nil {
			return entry, err
		}
	}
	for _, id := range projection.SourceIDs {
		if err := routingBatchCharge(budget, 128+int64(len(id))*12, 128); err != nil {
			return entry, err
		}
	}
	if len(peering) == 1 {
		projection.Peering, err = routingCapturePeeringMatch(ctx, lookup, peering[0], budget)
		if err != nil {
			return entry, err
		}
	}
	copy(projection.FactsID[:], crypto.Hash(header.objects[:]))
	return routingQueryCaptureCache{lookup: lookup, projection: projection, current: true}, nil
}

func routingQueryCaptureMatches(lookup BGPRoutingFlowLookup, read flowstore.RoutingCaptureRead, header routingQueryCaptureHeader) bool {
	owner, input, at := lookup.Owner, read.Witness.Input, read.Ref.CapturedAt
	if owner.ContextID != header.contextID || owner.AgentID != read.Sender || owner.Exporter != input.Exporter.Unmap() || owner.Protocol != input.Protocol || owner.Domain != input.Domain || owner.ObservedAt.After(at) || !owner.ValidUntil.After(at) {
		return false
	}
	for i, side := range []BGPRoutingFlowSide{lookup.Source, lookup.Destination} {
		address := input.Source.Unmap()
		if i == 1 {
			address = input.Destination.Unmap()
		}
		if side.State != "router_selected" {
			continue
		}
		if !side.Route.Prefix.Contains(address) || side.Route.Source.ObservedAt.After(at) || side.Route.AsOf.After(at) || !side.Route.ValidUntil.After(at) {
			return false
		}
		for _, hop := range side.NextHops {
			if hop.ASN != nil && !hop.ValidUntil.After(at) {
				return false
			}
		}
	}
	return !at.IsZero() && at.After(time.Unix(0, 0))
}
