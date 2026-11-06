// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"reflect"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// A routing target is a delegation from the existing base source, never a new
// collector assignment. Recheck both credentials before accepting that target;
// current operator metadata alone cannot authenticate a retained generation.
func boundRoutingSourceAuthority(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, lock bool) (BGPRoutingSourceAuthority, error) {
	selected := source.routingSelection
	if !validRoutingSelection(source, selected) {
		return BGPRoutingSourceAuthority{}, ErrBGPRoutingSourceUnavailable
	}
	base := source
	base.routingSelection = nil
	base.ContextID, base.RouterID = selected.BaseContextID, selected.BaseRouterID
	authority, err := routingCredentialAuthority(ctx, sc, base, lock, selected.Epoch)
	if err != nil {
		return BGPRoutingSourceAuthority{}, err
	}
	profile := BGPRoutingBudget{MemoryBytes: 256 << 20, WorkUnits: 256 << 20, StateBytes: 1 << 30}
	config, err := loadRoutingSourceConfiguration(ctx, sc, base.CollectorAgentID, base.SourceRef, profile)
	if err != nil {
		return BGPRoutingSourceAuthority{}, err
	}
	identifier, err := netip.ParseAddr(selected.Binding.BGPIdentifier)
	if err != nil {
		return BGPRoutingSourceAuthority{}, ErrBGPRoutingSourceUnavailable
	}
	peer := BGPRoutingPeer{Type: 3, BGPIdentifier: identifier}
	if _, err := hex.Decode(peer.Distinguisher[:], []byte(selected.Binding.Distinguisher)); err != nil {
		return BGPRoutingSourceAuthority{}, ErrBGPRoutingSourceUnavailable
	}
	current, err := selectRoutingSource(ctx, sc, config, peer, selected.Families)
	if err != nil {
		return BGPRoutingSourceAuthority{}, err
	}
	if !sameRoutingSelection(current, *selected) {
		return BGPRoutingSourceAuthority{}, ErrBGPRoutingSourceUnavailable
	}
	if lock {
		// The base source row is already locked. Hold the delegated target too;
		// deleting/recreating its UUID cannot cross publication or a route write.
		var routerBorn, contextBorn time.Time
		err := sc.Q.QueryRow(ctx, `SELECT router.created_at,target.created_at FROM entities router
 JOIN entity_contexts target ON (target.tenant_id,target.id)=(router.tenant_id,router.context_id)
 WHERE router.tenant_id=$1 AND router.context_id=$2 AND router.id=$3 AND router.kind='device'
 FOR SHARE OF router,target`, source.TenantID, source.ContextID, source.RouterID).Scan(&routerBorn, &contextBorn)
		if err != nil || routerBorn.After(selected.AssignedAt) || contextBorn.After(selected.AssignedAt) {
			return BGPRoutingSourceAuthority{}, ErrBGPRoutingSourceUnavailable
		}
	}
	return authority, nil
}

func validRoutingSelection(source BGPRoutingSource, selected *routingSourceSelection) bool {
	if selected == nil || selected.ContextID != source.ContextID || selected.RouterID != source.RouterID ||
		selected.Binding.ContextID != source.ContextID || selected.Binding.RouterID != source.RouterID ||
		selected.BindingID != selected.Binding.ID || selected.AssignedAt.IsZero() || selected.AssignedAt.After(source.ObservedAt) {
		return false
	}
	for _, id := range []string{selected.BaseContextID, selected.BaseRouterID, selected.Epoch, selected.BindingID} {
		if canonical, err := validRegistryUUID(id); err != nil || canonical != id {
			return false
		}
	}
	canonical := selected.Binding
	if normalizeRoutingBinding(&canonical) != nil || !reflect.DeepEqual(canonical, selected.Binding) {
		return false
	}
	if len(selected.Families) == 0 || len(selected.Families) > 2 {
		return false
	}
	var seen [3]bool
	for _, afi := range selected.Families {
		if afi < 1 || afi > 2 || seen[afi] {
			return false
		}
		seen[afi] = true
		permitted := false
		for _, declared := range selected.Binding.Families {
			permitted = permitted || afi == declared
		}
		if !permitted {
			return false
		}
	}
	return true
}

func decodeRoutingSelection(ctx context.Context, raw []byte, source BGPRoutingSource, budget BGPRoutingBudget) (*routingSourceSelection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(raw) == 0 || routingBatchPopulationCharge(&budget, len(raw), 128, 16) != nil {
		return nil, ErrBGPRoutingBudget
	}
	var selected routingSourceSelection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&selected) != nil || !validRoutingSelection(source, &selected) {
		return nil, ErrBGPRoutingView
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, ErrBGPRoutingView
	}
	return &selected, nil
}

func routingSelectionSupportsAFI(source BGPRoutingSource, afi uint16) bool {
	if source.routingSelection == nil {
		return true
	}
	for _, permitted := range source.routingSelection.Families {
		if afi == permitted {
			return true
		}
	}
	return false
}

func sameRoutingSelection(a, b routingSourceSelection) bool {
	return a.BaseContextID == b.BaseContextID && a.BaseRouterID == b.BaseRouterID &&
		a.ContextID == b.ContextID && a.RouterID == b.RouterID && a.Epoch == b.Epoch && a.BindingID == b.BindingID &&
		a.AssignedAt.Equal(b.AssignedAt) && reflect.DeepEqual(a.Binding, b.Binding) && reflect.DeepEqual(a.Families, b.Families)
}

func routingSelectionJSON(source BGPRoutingSource) (any, error) {
	if source.routingSelection == nil {
		return nil, nil
	}
	if !validRoutingSelection(source, source.routingSelection) {
		return nil, ErrBGPRoutingView
	}
	body, err := json.Marshal(source.routingSelection)
	if err != nil {
		return nil, err
	}
	return string(body), nil
}

func routingStoredViewKind(source BGPRoutingSource, definition BGPRoutingViewDefinition) (string, error) {
	if source.routingSelection == nil {
		return definition.Kind, nil
	}
	selected := source.routingSelection
	if !validRoutingSelection(source, selected) || definition.Kind != "loc_rib" || definition.Peer.Type != 3 || definition.SAFI != 1 ||
		definition.Peer.BGPIdentifier.String() != selected.Binding.BGPIdentifier || hex.EncodeToString(definition.Peer.Distinguisher[:]) != selected.Binding.Distinguisher {
		return "", ErrBGPRoutingView
	}
	for _, afi := range selected.Families {
		if afi == definition.AFI {
			return "operator_loc_rib", nil
		}
	}
	return "", ErrBGPRoutingView
}
