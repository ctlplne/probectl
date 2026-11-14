// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// RoutingChangeAuthorizer checks the current user and the exact current source
// resources in the same tenant snapshot. Original labels never supply grants.
type RoutingChangeAuthorizer func(context.Context, tenancy.Scope, BGPRoutingSource, change.Event) error

type routingChangeRequest struct {
	Ordinal    int                    `json:"ordinal"`
	ID         string                 `json:"id"`
	Prefix     string                 `json:"prefix"`
	OccurredAt time.Time              `json:"occurred_at"`
	Routing    *change.RouteReference `json:"routing"`
}

// VerifyRoutingChangeReferencesInScope fetches private source bodies only from
// exact owned rows under FORCE-RLS. One streaming query avoids a round trip per
// prefix. Identical original batch headers share source validation, while each
// event still receives its own current resource/ABAC check.
func (ChangeEvents) VerifyRoutingChangeReferencesInScope(ctx context.Context, sc tenancy.Scope, events []change.Event, memory int64, authorize RoutingChangeAuthorizer) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return entity.ErrScopeMismatch
	}
	if len(events) == 0 {
		return ctx.Err()
	}
	if authorize == nil {
		return errRoutingChangeSource
	}
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return err
	}
	if memory < 4096 || int64(len(events)) > memory/1024 || memory > math.MaxInt64/8 {
		return ErrBGPRoutingBudget
	}
	requested := make([]routingChangeRequest, 0, len(events))
	seenIDs := map[string]bool{}
	for index, event := range events {
		if event.TenantID != bound.String() {
			return entity.ErrScopeMismatch
		}
		id, err := validRegistryUUID(event.ID)
		if err != nil || id != event.ID || seenIDs[id] || event.Source != ownedRoutingChangeSource || event.Kind != change.KindRoute || event.Routing == nil || event.Routing.Validate() != nil || event.Target != event.Routing.RouterID || event.OccurredAt.IsZero() {
			return change.ErrRouteReference
		}
		prefix, err := netip.ParsePrefix(event.Prefix)
		if err != nil || prefix.Masked() != prefix || prefix.String() != event.Prefix || prefix.Addr().Is4() != (event.Routing.AFI == 1) {
			return change.ErrRouteReference
		}
		seenIDs[id] = true
		requested = append(requested, routingChangeRequest{index, id, event.Prefix, event.OccurredAt, event.Routing})
	}
	body, err := json.Marshal(requested)
	if err != nil {
		return err
	}
	if int64(len(body)) > memory/4 {
		return ErrBGPRoutingBudget
	}
	remaining := memory - int64(len(body))*4 - memory/16
	if remaining < 0 {
		return ErrBGPRoutingBudget
	}
	work := memory * 8
	profile := BGPRoutingBudget{MemoryBytes: memory, WorkUnits: work, StateBytes: memory}
	rows, err := sc.Q.Query(ctx, `SELECT requested.ordinal,
 CASE WHEN octet_length(events.routing_source::text)::bigint<=$3::bigint/16 THEN events.routing_source::text END
 FROM jsonb_to_recordset($2::jsonb) AS requested(ordinal bigint,id uuid,prefix text,occurred_at timestamptz,routing jsonb)
 LEFT JOIN change_events events ON events.tenant_id=$1 AND events.id=requested.id
 AND events.source=$4 AND events.kind='route' AND events.prefix=requested.prefix
 AND events.occurred_at=requested.occurred_at AND events.routing=requested.routing
 ORDER BY requested.ordinal`, bound.String(), body, memory, ownedRoutingChangeSource)
	if err != nil {
		return err
	}
	defer rows.Close()
	type admittedSource struct{ original routingChangeSource }
	cache := map[string]int{}
	sources := []admittedSource{}
	eventSources := make([]int, len(events))
	seen := make([]bool, len(events))
	count := 0
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var ordinal int64
		var raw []byte
		if err := rows.Scan(&ordinal, &raw); err != nil {
			return err
		}
		if ordinal < 0 || ordinal >= int64(len(events)) || seen[int(ordinal)] || len(raw) == 0 {
			return errRoutingChangeSource
		}
		seen[int(ordinal)] = true
		count++
		if int64(len(raw)) > memory/16 || int64(len(raw)) > work/16 {
			return ErrBGPRoutingBudget
		}
		work -= int64(len(raw)) * 16
		key := hex.EncodeToString(crypto.Hash(raw))
		input := events[int(ordinal)]
		index, exists := cache[key]
		if !exists {
			if int64(len(raw)) > remaining/16 {
				return ErrBGPRoutingBudget
			}
			original, err := decodeRoutingChangeSource(ctx, sc, raw, *input.Routing, profile)
			if err != nil {
				return err
			}
			index = len(sources)
			sources = append(sources, admittedSource{original})
			cache[key] = index
			remaining -= int64(len(raw)) * 16
		} else if !sameRoutingChangeOriginal(sources[index].original, *input.Routing) {
			return change.ErrRouteReference
		}
		eventSources[int(ordinal)] = index
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if count != len(events) {
		return errRoutingChangeSource
	}
	// The streaming result must close before source/current-user callbacks use
	// this transaction connection. It is never a nested query on an active rowset.
	var earliest time.Time
	for _, source := range sources {
		until, err := verifyRoutingChangeSourceInScope(ctx, sc, source.original)
		if err != nil {
			return err
		}
		if earliest.IsZero() || until.Before(earliest) {
			earliest = until
		}
	}
	for index, input := range events {
		if err := authorize(ctx, sc, sources[eventSources[index]].original.Source, input); err != nil {
			return err
		}
	}
	if earliest.IsZero() || !time.Now().UTC().Before(earliest) {
		return errRoutingChangeSource
	}
	return ctx.Err()
}

func sameRoutingChangeOriginal(original routingChangeSource, reference change.RouteReference) bool {
	baseContext, baseRouter := original.Source.ContextID, original.Source.RouterID
	if selected := original.Source.routingSelection; selected != nil {
		baseContext, baseRouter = selected.BaseContextID, selected.BaseRouterID
	}
	return reference.ContextID == original.Source.ContextID && reference.RouterID == original.Source.RouterID && reference.BaseContextID == baseContext && reference.BaseRouterID == baseRouter && reference.ViewID == original.ViewID && reference.Generation == original.Generation && reference.Sequence == original.Sequence && reference.BatchDigest == original.BatchDigest && reference.View == original.View && reference.AFI == original.AFI && reference.SAFI == original.SAFI && reference.ObservedAt.Equal(original.Source.ObservedAt)
}
