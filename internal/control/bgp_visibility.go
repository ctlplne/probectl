// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	Monitor        store.BGPVisibilityMonitor       `json:"monitor"`
	Items          []store.BGPVisibilityObservation `json:"items"`
	Coverage       string                           `json:"coverage"`
	EffectiveLimit int                              `json:"effective_limit"`
	NextCursor     string                           `json:"next_cursor,omitempty"`
}

type bgpVisibilityCursor struct {
	Monitor  string                      `json:"monitor"`
	Before   time.Time                   `json:"before"`
	Position store.BGPVisibilityPosition `json:"position"`
}

func parseBGPVisibilityHistory(id, before, cursor string) (bgpVisibilityCursor, error) {
	if cursor != "" {
		var out bgpVisibilityCursor
		if before != "" || len(cursor) > 512 {
			return out, apierror.Validation("provide a visibility cursor or a before timestamp")
		}
		body, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || json.Unmarshal(body, &out) != nil || out.Monitor != id || out.Before.IsZero() || out.Position.ObservedAt.IsZero() {
			return out, apierror.Validation("invalid visibility cursor")
		}
		return out, nil
	}
	out := bgpVisibilityCursor{Monitor: id, Before: time.Now().UTC()}
	if before != "" {
		var err error
		out.Before, err = time.Parse(time.RFC3339Nano, before)
		if err != nil {
			return out, apierror.Validation("before must be an RFC 3339 timestamp")
		}
	}
	return out, nil
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
	query := r.URL.Query()
	page, err := parseBGPVisibilityHistory(r.PathValue("id"), query.Get("before"), query.Get("cursor"))
	if err != nil {
		return err
	}
	var out bgpVisibilityHistory
	err = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = readBGPVisibilityHistory(ctx, sc, page, limit)
		return err
	})
	if err != nil {
		return bgpVisibilityAPIError(err)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func readBGPVisibilityHistory(ctx context.Context, sc tenancy.Scope, page bgpVisibilityCursor, limit int) (bgpVisibilityHistory, error) {
	monitor, err := store.BGPVisibilityMonitorInScope(ctx, sc, page.Monitor)
	if err != nil {
		return bgpVisibilityHistory{}, err
	}
	var after *store.BGPVisibilityPosition
	if !page.Position.ObservedAt.IsZero() {
		after = &page.Position
	}
	items, more, err := (store.BGPVisibility{}).History(ctx, sc, page.Monitor, page.Before, after, limit)
	if err != nil {
		return bgpVisibilityHistory{}, err
	}
	out := bgpVisibilityHistory{Monitor: monitor, Items: items, Coverage: "no_retained_points", EffectiveLimit: limit}
	if len(items) > 0 {
		out.Coverage = "retained_points"
	}
	if more {
		last := items[len(items)-1]
		page.Position = store.BGPVisibilityPosition{ObservedAt: last.ObservedAt, Source: last.Source, Collector: last.Collector}
		body, err := json.Marshal(page)
		if err != nil {
			return bgpVisibilityHistory{}, err
		}
		out.NextCursor = base64.RawURLEncoding.EncodeToString(body)
	}
	return out, nil
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
