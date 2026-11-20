// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type saveBGPVisibilityMonitor struct {
	Prefix                    netip.Prefix `json:"prefix"`
	MinimumVisibleBasisPoints int          `json:"minimum_visible_basis_points"`
	AlertOnPartial            bool         `json:"alert_on_partial"`
	AlertOnLoss               bool         `json:"alert_on_loss"`
}

type bgpVisibilityMonitors struct {
	Items []store.BGPVisibilityMonitor `json:"items"`
}

type bgpVisibilityHistory struct {
	Monitor store.BGPVisibilityMonitor       `json:"monitor"`
	Items   []store.BGPVisibilityObservation `json:"items"`
}

func (s *Server) handleListBGPVisibility(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("BGP visibility storage is unavailable")
	}
	var out bgpVisibilityMonitors
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out.Items, err = (store.BGPVisibility{}).ListMonitors(ctx, sc)
		return err
	})
	if err != nil {
		return bgpVisibilityAPIError(err)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handleSaveBGPVisibility(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("BGP visibility storage is unavailable")
	}
	var input saveBGPVisibilityMonitor
	if err := decodeJSONLimit(r, 4096, &input); err != nil {
		return err
	}
	var out store.BGPVisibilityMonitor
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = (store.BGPVisibility{}).SaveMonitor(ctx, sc, store.BGPVisibilityMonitor{
			Prefix: input.Prefix, MinimumVisibleBasisPoints: input.MinimumVisibleBasisPoints,
			AlertOnPartial: input.AlertOnPartial, AlertOnLoss: input.AlertOnLoss})
		return err
	})
	if err != nil {
		return bgpVisibilityAPIError(err)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handleGetBGPVisibility(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("BGP visibility storage is unavailable")
	}
	limit, err := intParam(r, "limit", 100)
	if err != nil {
		return err
	}
	before, err := bgpVisibilityCutoff(r.URL.Query().Get("before"))
	if err != nil {
		return err
	}
	var out bgpVisibilityHistory
	err = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = readBGPVisibilityHistory(ctx, sc, r.PathValue("id"), before, limit)
		return err
	})
	if err != nil {
		return bgpVisibilityAPIError(err)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func readBGPVisibilityHistory(ctx context.Context, sc tenancy.Scope, id string, before time.Time, limit int) (bgpVisibilityHistory, error) {
	monitor, err := store.BGPVisibilityMonitorInScope(ctx, sc, id)
	if err != nil {
		return bgpVisibilityHistory{}, err
	}
	items, err := (store.BGPVisibility{}).History(ctx, sc, id, before, limit)
	if err != nil {
		return bgpVisibilityHistory{}, err
	}
	return bgpVisibilityHistory{Monitor: monitor, Items: items}, nil
}

func (s *Server) handleDeleteBGPVisibility(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("BGP visibility storage is unavailable")
	}
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.BGPVisibility{}).DeleteMonitor(ctx, sc, r.PathValue("id"))
	})
	if err != nil {
		return bgpVisibilityAPIError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func bgpVisibilityAPIError(err error) error {
	switch {
	case errors.Is(err, store.ErrBGPVisibilityMissing):
		return apierror.NotFound("BGP visibility monitor not found")
	case errors.Is(err, store.ErrBGPVisibilityInput):
		return apierror.Validation("invalid BGP visibility monitor or history selection")
	default:
		return err
	}
}
