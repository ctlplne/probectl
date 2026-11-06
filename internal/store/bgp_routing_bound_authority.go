// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
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
	copy := selected.Binding
	if normalizeRoutingBinding(&copy) != nil || !reflect.DeepEqual(copy, selected.Binding) {
		return false
	}
	return true
}

func sameRoutingSelection(a, b routingSourceSelection) bool {
	return a.BaseContextID == b.BaseContextID && a.BaseRouterID == b.BaseRouterID &&
		a.ContextID == b.ContextID && a.RouterID == b.RouterID && a.Epoch == b.Epoch && a.BindingID == b.BindingID &&
		a.AssignedAt.Equal(b.AssignedAt) && reflect.DeepEqual(a.Binding, b.Binding) && reflect.DeepEqual(a.Families, b.Families)
}
