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
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type bmpSessionHistoryArgs struct {
	Source                                 store.BMPSessionSource
	From, To, Peer, Cursor                 string
	Statistic, AFI, SAFI, Minimum, Maximum string
	Limit                                  int
}

type bmpSessionHistoryCursor struct {
	Version int                              `json:"version"`
	Query   store.BMPSessionHistorySelection `json:"query"`
	Range   *bgp.BMPStatisticRange           `json:"range,omitempty"`
}

type bmpSessionHistoryPage struct {
	Source         store.BMPSessionSource   `json:"source"`
	Items          []bmpSessionHistoryPoint `json:"items"`
	Range          *bgp.BMPStatisticRange   `json:"expected_range,omitempty"`
	Coverage       string                   `json:"coverage"`
	EffectiveLimit int                      `json:"effective_limit"`
	NextCursor     string                   `json:"next_cursor,omitempty"`
}

type bmpSessionHistoryPoint struct {
	store.BMPSessionHistoryPoint
	RangeStatus string `json:"range_status,omitempty"`
}

func bmpStatRangeRequested(args bmpSessionHistoryArgs) bool {
	return args.Statistic != "" || args.AFI != "" || args.SAFI != "" || args.Minimum != "" || args.Maximum != ""
}

func parseBMPStatRange(args bmpSessionHistoryArgs) (*bgp.BMPStatisticRange, error) {
	if !bmpStatRangeRequested(args) {
		return nil, nil
	}
	spec := bgp.BMPStatisticRange{}
	stat, errStat := strconv.ParseUint(args.Statistic, 10, 16)
	minimum, errMin := strconv.ParseUint(args.Minimum, 10, 64)
	maximum, errMax := strconv.ParseUint(args.Maximum, 10, 64)
	if errStat != nil || errMin != nil || errMax != nil {
		return nil, apierror.Validation("a gauge type and exact unsigned minimum and maximum are required")
	}
	spec.Minimum, spec.Maximum, spec.Type = minimum, maximum, uint16(stat)
	if args.AFI != "" || args.SAFI != "" {
		afi, errAFI := strconv.ParseUint(args.AFI, 10, 16)
		safi, errSAFI := strconv.ParseUint(args.SAFI, 10, 8)
		if errAFI != nil || errSAFI != nil || afi == 0 || safi == 0 {
			return nil, apierror.Validation("the expected range must select a valid AFI and SAFI pair")
		}
		spec.AFI, spec.SAFI = uint16(afi), uint8(safi)
	}
	if !spec.Valid() {
		return nil, apierror.Validation("the gauge, address family or expected range is invalid")
	}
	return &spec, nil
}

func parseBMPSessionHistoryArgs(args bmpSessionHistoryArgs) (bmpSessionHistoryCursor, error) {
	out := bmpSessionHistoryCursor{Version: 1, Query: store.BMPSessionHistorySelection{Source: args.Source, Peer: args.Peer}}
	if args.Cursor != "" {
		if len(args.Cursor) > 4096 || args.From != "" || args.To != "" || args.Peer != "" || bmpStatRangeRequested(args) {
			return out, apierror.Validation("continue the original BMP session selection")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(args.Cursor)
		if err != nil || json.Unmarshal(decoded, &out) != nil || out.Version != 1 || out.Query.Source != args.Source || out.Query.After == nil || out.Range != nil && !out.Range.Valid() {
			return out, apierror.Validation("invalid BMP session cursor")
		}
	} else {
		var err error
		out.Range, err = parseBMPStatRange(args)
		if err != nil {
			return out, err
		}
		now := time.Now().UTC()
		out.Query.From, out.Query.To = now.Add(-24*time.Hour), now
		for _, item := range []struct {
			raw    string
			target *time.Time
		}{{args.From, &out.Query.From}, {args.To, &out.Query.To}} {
			if item.raw == "" {
				continue
			}
			value, err := time.Parse(time.RFC3339Nano, item.raw)
			if err != nil {
				return out, apierror.Validation("BMP session time bounds must be RFC 3339 timestamps")
			}
			*item.target = value.UTC()
		}
	}
	if out.Range != nil && out.Query.Peer == "" {
		return out, apierror.Validation("select a neighbor for a comparable BMP gauge range")
	}
	out.Query.Limit = args.Limit
	return out, nil
}

func (s *Server) handleBMPSessionHistory(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	limit, err := intParam(r, "limit", 100)
	if err != nil {
		return err
	}
	cursor, err := parseBMPSessionHistoryArgs(bmpSessionHistoryArgs{Source: store.BMPSessionSource{ContextID: q.Get("context_id"),
		RouterID: r.PathValue("router_id"), CollectorAgentID: q.Get("collector_agent_id"), SourceRef: q.Get("source_ref")},
		From: q.Get("from"), To: q.Get("to"), Peer: q.Get("peer"), Cursor: q.Get("cursor"), Limit: limit,
		Statistic: q.Get("statistic"), AFI: q.Get("afi"), SAFI: q.Get("safi"), Minimum: q.Get("expected_min"), Maximum: q.Get("expected_max")})
	if err != nil {
		return err
	}
	page, err := s.readBMPSessionHistory(r.Context(), auth.PrincipalFrom(r.Context()), cursor, false)
	if err != nil {
		return bmpSessionHistoryError(err)
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

func (s *Server) readBMPSessionHistory(ctx context.Context, actor *auth.Principal, cursor bmpSessionHistoryCursor, native bool) (bmpSessionHistoryPage, error) {
	out := bmpSessionHistoryPage{Source: cursor.Query.Source, EffectiveLimit: cursor.Query.Limit, Coverage: "no_retained_points", Range: cursor.Range}
	if s.pool == nil {
		return out, apierror.Unavailable("BMP session storage is unavailable")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return out, err
	}
	if s.requireMFA && !actor.MFASatisfied {
		return out, apierror.Forbidden("multi-factor authentication required")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return out, apierror.Unavailable("BMP session admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if s.fairnessGate != nil {
		release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
		if err != nil {
			return out, err
		}
		defer release()
	}
	profile := store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.MemoryBytes / 2, StateBytes: budget.MemoryBytes}
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		checked, principal, err := s.currentRoutingAuthority(ctx, sc, actor, ai.PermEventsRead)
		if err != nil {
			return err
		}
		if native {
			if err := s.authorize(checked, principal, permAIQuery, auth.RBACGlobal, nil); err != nil {
				return err
			}
		}
		authorizePeer, err := s.bmpSessionSourceAuthorizer(checked, sc, principal, cursor.Query.Source)
		if err != nil {
			return err
		}
		if err := authorizePeer(cursor.Query.Peer); err != nil {
			return err
		}
		points, more, err := store.BMPSessionHistoryInScope(checked, sc, cursor.Query, profile)
		if err != nil {
			return err
		}
		out.Items = make([]bmpSessionHistoryPoint, 0, len(points))
		authorized := map[string]bool{"": true, cursor.Query.Peer: true}
		for _, point := range points {
			peer := bmpSessionPointPeer(point)
			if !authorized[peer] {
				if err := authorizePeer(peer); err != nil {
					return err
				}
				authorized[peer] = true
			}
			row := bmpSessionHistoryPoint{BMPSessionHistoryPoint: point}
			if cursor.Range != nil && point.Statistics != nil {
				row.RangeStatus = cursor.Range.Evaluate(point.Statistics, point.CoverageGap)
			}
			out.Items = append(out.Items, row)
		}
		if len(points) != 0 {
			out.Coverage = "retained_points"
		}
		if more {
			last := points[len(points)-1].BMPSessionHistoryPosition
			cursor.Query.After = &last
			raw, err := json.Marshal(cursor)
			if err != nil {
				return err
			}
			out.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
		}
		return checked.Err()
	})
	return out, err
}

func (s *Server) bmpSessionSourceAuthorizer(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, source store.BMPSessionSource) (func(string) error, error) {
	if err := store.VerifyBMPSessionSourceInScope(ctx, sc, source); err != nil {
		return nil, err
	}
	record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, source.ContextID)
	if err != nil {
		return nil, err
	}
	resource := entityContextResource(record)
	resource["entity_id"], resource["agent_id"], resource["source_ref"] = source.RouterID, source.CollectorAgentID, source.SourceRef
	resource["source_kind"] = string(entity.BMPPeer)
	return func(peer string) error {
		resource["peer_address"] = peer
		for _, permission := range []string{ai.PermEventsRead, ai.PermEntitiesRead} {
			if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

func bmpSessionPointPeer(point store.BMPSessionHistoryPoint) string {
	var address netip.Addr
	switch {
	case point.Neighbor != nil:
		address = point.Neighbor.Peer.PeerAddress
	case point.Statistics != nil:
		address = point.Statistics.Peer.PeerAddress
	case point.UpdateChurn != nil:
		address = point.UpdateChurn.Peer.PeerAddress
	}
	if address.IsValid() {
		return address.String()
	}
	return ""
}

func bmpSessionHistoryError(err error) error {
	switch {
	case errors.Is(err, store.ErrBGPRoutingBudget):
		return apierror.RateLimited("the complete BMP session page exceeds resource admission")
	case errors.Is(err, store.ErrBGPRoutingSourceUnavailable), errors.Is(err, pgx.ErrNoRows):
		return apierror.NotFound("the current BMP session source is unavailable")
	case errors.Is(err, store.ErrBMPSessionEvidenceInput):
		return apierror.Validation("invalid BMP session scope or history selection")
	default:
		return entityAdminError(err)
	}
}
