// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package change

import (
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
)

var ErrRouteReference = errors.New("change: invalid original routing reference")

// RouteReference identifies an original accepted owned-router update. It is
// metadata, never a tenant/context/source grant. The storage reader separately
// verifies its original source and current authority before publication.
// Sequence is decimal text so JavaScript never rounds a retained sequence.
type RouteReference struct {
	Version           int       `json:"version"`
	ContextID         string    `json:"context_id"`
	RouterID          string    `json:"router_id"`
	BaseContextID     string    `json:"base_context_id"`
	BaseRouterID      string    `json:"base_router_id"`
	ViewID            string    `json:"view_id"`
	Generation        string    `json:"generation"`
	Sequence          string    `json:"sequence"`
	UpdateIndex       int       `json:"update_index"`
	BatchDigest       string    `json:"batch_digest"`
	ObservedAt        time.Time `json:"observed_at"`
	View              string    `json:"view"`
	Action            string    `json:"action"`
	AFI               uint16    `json:"afi"`
	SAFI              uint8     `json:"safi"`
	HasPathID         bool      `json:"has_path_id"`
	PathID            uint32    `json:"path_id"`
	PriorPresent      bool      `json:"prior_present"`
	PathChanged       bool      `json:"path_changed"`
	AttributesChanged bool      `json:"attributes_changed"`
}

func (reference RouteReference) Validate() error {
	if reference.UpdateIndex < 0 || reference.Version != 1 || reference.ObservedAt.IsZero() || reference.SAFI != 1 || (reference.AFI != 1 && reference.AFI != 2) || (!reference.HasPathID && reference.PathID != 0) {
		return ErrRouteReference
	}
	for _, value := range []string{reference.ContextID, reference.RouterID, reference.BaseContextID, reference.BaseRouterID, reference.ViewID, reference.Generation} {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return ErrRouteReference
		}
	}
	sequence, err := strconv.ParseInt(reference.Sequence, 10, 64)
	if err != nil || sequence <= 0 || strconv.FormatInt(sequence, 10) != reference.Sequence {
		return ErrRouteReference
	}
	digest, err := hex.DecodeString(reference.BatchDigest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != reference.BatchDigest {
		return ErrRouteReference
	}
	switch reference.View {
	case "adj_rib_in_pre_policy", "adj_rib_in_post_policy", "adj_rib_out_pre_policy", "adj_rib_out_post_policy", "loc_rib", "operator_loc_rib":
	default:
		return ErrRouteReference
	}
	switch reference.Action {
	case "announcement":
	case "withdrawal":
		if reference.PathChanged || reference.AttributesChanged {
			return ErrRouteReference
		}
	case "selected_route_update":
		if (reference.View != "loc_rib" && reference.View != "operator_loc_rib") || !reference.PriorPresent || (!reference.PathChanged && !reference.AttributesChanged) {
			return ErrRouteReference
		}
	default:
		return ErrRouteReference
	}
	if !reference.PriorPresent && (reference.PathChanged || reference.AttributesChanged) {
		return ErrRouteReference
	}
	return nil
}
