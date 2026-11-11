// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PeeringQueryTarget selects one private operation, never a query-JSON grant.
type PeeringQueryTarget struct {
	entity.Scope
	RouterID  string
	PeerASN   uint32
	Direction string
}

type peeringQueryStates struct{ Source, Destination string }

// PeeringQueryData binds original capture references and complete path-match
// states to one target/direction. Current grants, roles and IX generations must
// still be rechecked before publication; this digest never authorizes a read.
type PeeringQueryData struct {
	target  PeeringQueryTarget
	routing *RoutingQueryData
	states  map[routingQueryKey]peeringQueryStates
	digest  string
}

// NewPeeringQueryData consumes only server-selected current-authority capture
// projections. Native routing fields retain their existing meaning and digest;
// the separate peering digest also covers target, direction and both states.
func NewPeeringQueryData(ctx context.Context, target PeeringQueryTarget, at time.Time, rows []RoutingProjection, maxBytes int64) (*PeeringQueryData, error) {
	bound, present := tenancy.FromContext(ctx)
	scope, err := target.Normalize()
	if !present || err != nil || scope != target.Scope || bound.String() != target.TenantID || !validTagProjectionID(target.RouterID) || target.PeerASN == 0 || (target.Direction != "inbound" && target.Direction != "outbound") {
		return nil, ErrRoutingQueryScope
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	count := int64(len(rows))
	// Extra maps, sorting, canonical wire copies and the operation header are
	// admitted alongside all native references/facts. No row/page cap applies.
	if maxBytes < 4096 || count > (maxBytes-4096)/1024 {
		return nil, ErrExplorerBudget
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if row.Scope != target.Scope || row.Peering == nil || row.Peering.RouterID != target.RouterID || row.Peering.PeerASN != target.PeerASN || !validPeeringQueryState(row.Peering.Source) || !validPeeringQueryState(row.Peering.Destination) {
			return nil, ErrRoutingQueryScope
		}
	}
	reserved := 4096 + count*1024
	routing, err := NewRoutingQueryData(ctx, target.TenantID, at, rows, maxBytes-reserved)
	if err != nil {
		return nil, err
	}
	type reference struct {
		Key   [32]byte
		Clock int64
		peeringQueryStates
	}
	refs := make([]reference, 0, len(rows))
	data := &PeeringQueryData{target: target, routing: routing, states: make(map[routingQueryKey]peeringQueryStates, len(rows))}
	facts := map[[32]byte]peeringQueryStates{}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := routingQueryKey{row.Key, row.Clock}
		states := peeringQueryStates{row.Peering.Source, row.Peering.Destination}
		factID := routing.byKey[key]
		if previous, found := facts[factID]; found && previous != states {
			return nil, ErrRoutingQueryScope
		}
		facts[factID] = states
		data.states[key] = states
		refs = append(refs, reference{row.Key, row.Clock, states})
	}
	slices.SortFunc(refs, func(a, b reference) int { return slices.Compare(a.Key[:], b.Key[:]) })
	body, err := json.Marshal(struct {
		Target     PeeringQueryTarget
		Routing    string
		References []reference
	}{target, routing.digest, refs})
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > reserved/2 {
		return nil, ErrExplorerBudget
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data.digest = hex.EncodeToString(crypto.Hash(body))
	return data, nil
}

func validPeeringQueryState(state string) bool {
	switch state {
	case "eligible", "not_on_path", "ambiguous", "unavailable":
		return true
	default:
		return false
	}
}

// Digest binds the whole immutable operation; it is not retained authority.
func (data *PeeringQueryData) Digest(ctx context.Context, tenant string) (string, error) {
	if data == nil || data.target.TenantID != tenant || data.digest == "" {
		return "", ErrRoutingQueryScope
	}
	if err := data.routing.validate(ctx, tenant); err != nil {
		return "", err
	}
	return data.digest, nil
}

func (data *PeeringQueryData) stateForRow(row Row) string {
	if data == nil || row.TenantID != data.target.TenantID || row.RoutingCaptureKey == "" || validateRoutingCaptureRow(row) != nil {
		return "unavailable"
	}
	body, _ := hex.DecodeString(row.RoutingCaptureKey)
	var key [32]byte
	copy(key[:], body)
	states, found := data.states[routingQueryKey{key, row.RoutingCapturedUnixNanos}]
	if !found {
		return "unavailable"
	}
	if data.target.Direction == "inbound" {
		return states.Source
	}
	return states.Destination
}
