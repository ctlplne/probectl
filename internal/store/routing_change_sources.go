// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const ownedRoutingChangeSource = "probectl-owned-bgp"

// Original source metadata lives on the existing change row, separately from
// its public reference. Generic webhook creation cannot set this column. The
// original routing selection is decoded by the same strict retained reader;
// neither this envelope nor its public reference conveys current authority.
type routingChangeSource struct {
	Version     int              `json:"version"`
	Source      BGPRoutingSource `json:"source"`
	Selection   json.RawMessage  `json:"selection,omitempty"`
	ViewBornAt  time.Time        `json:"view_born_at"`
	ViewID      string           `json:"view_id"`
	Generation  string           `json:"generation"`
	Sequence    string           `json:"sequence"`
	BatchDigest string           `json:"batch_digest"`
	View        string           `json:"view"`
	AFI         uint16           `json:"afi"`
	SAFI        uint8            `json:"safi"`
}

func decodeRoutingChangeSource(ctx context.Context, sc tenancy.Scope, raw []byte, reference change.RouteReference, profile BGPRoutingBudget) (routingChangeSource, error) {
	none := routingChangeSource{}
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil {
		return none, entity.ErrScopeMismatch
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if reference.Validate() != nil {
		return none, change.ErrRouteReference
	}
	if len(raw) == 0 {
		return none, errRoutingChangeSource
	}
	if routingBatchPopulationCharge(&profile, len(raw), 128, 16) != nil {
		return none, ErrBGPRoutingBudget
	}
	var original routingChangeSource
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&original); err != nil {
		return none, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || original.Version != 1 || original.ViewBornAt.IsZero() || original.Source.ObservedAt.Before(original.ViewBornAt) ||
		original.ViewID != reference.ViewID || original.Generation != reference.Generation || original.Sequence != reference.Sequence ||
		original.BatchDigest != reference.BatchDigest || original.View != reference.View || original.AFI != reference.AFI || original.SAFI != reference.SAFI ||
		original.Source.ContextID != reference.ContextID || original.Source.RouterID != reference.RouterID || !original.Source.ObservedAt.Equal(reference.ObservedAt) {
		return none, change.ErrRouteReference
	}
	if len(original.Selection) > 0 {
		selected, err := decodeRoutingSelection(ctx, original.Selection, original.Source, profile)
		if err != nil {
			return none, err
		}
		original.Source.routingSelection = selected
	}
	if err := validateBGPRoutingSource(ctx, sc, original.Source); err != nil {
		return none, err
	}
	baseContext, baseRouter := original.Source.ContextID, original.Source.RouterID
	if selected := original.Source.routingSelection; selected != nil {
		baseContext, baseRouter = selected.BaseContextID, selected.BaseRouterID
	}
	if reference.BaseContextID != baseContext || reference.BaseRouterID != baseRouter || !routingSelectionSupportsAFI(original.Source, original.AFI) {
		return none, change.ErrRouteReference
	}
	return original, ctx.Err()
}

// Source expiry/revocation and assignment/selector changes are current checks;
// a selected-view reference never substitutes for them. The birth observation
// also stays fixed, so a rebind cannot renew historical routing authority.
func verifyRoutingChangeSourceInScope(ctx context.Context, sc tenancy.Scope, original routingChangeSource) (time.Time, error) {
	current, err := (BGPRouting{}).sourceAuthorityInScope(ctx, sc, original.Source)
	if err != nil {
		return time.Time{}, err
	}
	birth := original.Source
	birth.ObservedAt = original.ViewBornAt
	originalBirth, err := (BGPRouting{}).sourceAuthorityInScope(ctx, sc, birth)
	if err != nil {
		return time.Time{}, err
	}
	return minRoutingTime(current.ValidUntil, originalBirth.ValidUntil), ctx.Err()
}

var errRoutingChangeSource = errors.New("original owned routing change source is unavailable")
