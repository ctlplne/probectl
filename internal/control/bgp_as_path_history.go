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

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type bgpASPathHistoryArgs struct {
	ID, From, To, Source, Vantage, Cursor string
	Limit                                 int
}

type bgpASPathHistoryCursor struct {
	Version int                             `json:"version"`
	Query   store.BGPASPathHistorySelection `json:"query"`
}

func parseBGPASPathHistoryArgs(args bgpASPathHistoryArgs) (bgpASPathHistoryCursor, error) {
	cursor := bgpASPathHistoryCursor{Version: 1}
	if args.Cursor != "" {
		if len(args.Cursor) > 2048 || args.From != "" || args.To != "" || args.Source != "" || args.Vantage != "" {
			return cursor, apierror.Validation("continue the original path history selection")
		}
		raw, err := base64.RawURLEncoding.DecodeString(args.Cursor)
		if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Version != 1 ||
			cursor.Query.Monitor != args.ID || cursor.Query.After == nil {
			return cursor, apierror.Validation("invalid AS path cursor")
		}
		cursor.Query.Limit = args.Limit
		return cursor, nil
	}
	now := time.Now().UTC()
	cursor.Query = store.BGPASPathHistorySelection{Monitor: args.ID, SourceKind: args.Source, Vantage: args.Vantage,
		From: now.Add(-30 * 24 * time.Hour), To: now, Limit: args.Limit}
	for _, bound := range []struct {
		value  string
		target *time.Time
	}{{args.From, &cursor.Query.From}, {args.To, &cursor.Query.To}} {
		if bound.value == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, bound.value)
		if err != nil {
			return cursor, apierror.Validation("AS path time bounds must be RFC 3339 timestamps")
		}
		*bound.target = parsed.UTC()
	}
	return cursor, nil
}

type bgpASPathStage struct {
	Segments    []bgp.ASPathSegment          `json:"segments"`
	Facts       bgp.ASPathFacts              `json:"facts"`
	AS4Action   string                       `json:"as4_action,omitempty"`
	Original    *store.BGPASPathPublicSource `json:"original,omitempty"`
	ObservedAt  *time.Time                   `json:"observed_at,omitempty"`
	Sequence    int64                        `json:"sequence,omitempty,string"`
	UpdateIndex *int                         `json:"update_index,omitempty"`
	NextHops    []netip.Addr                 `json:"next_hops,omitempty"`
}

type bgpASPathHistoryRow struct {
	store.BGPASPathHistoryRecord
	Previous      *bgpASPathStage              `json:"previous,omitempty"`
	Current       *bgpASPathStage              `json:"current,omitempty"`
	Changes       *bgp.ASPathChanges           `json:"changes,omitempty"`
	PublicSource  *store.BGPASPathPublicSource `json:"public_source,omitempty"`
	RouterView    string                       `json:"router_view,omitempty"`
	OriginalClock *time.Time                   `json:"original_clock,omitempty"`
	Incidents     []store.BGPASPathIncident    `json:"incidents,omitempty"`
}

type bgpASPathHistoryPage struct {
	Monitor        store.BGPVisibilityMonitor `json:"monitor"`
	Items          []bgpASPathHistoryRow      `json:"items"`
	Coverage       string                     `json:"coverage"`
	EffectiveLimit int                        `json:"effective_limit"`
	NextCursor     string                     `json:"next_cursor,omitempty"`
}

func (s *Server) handleBGPASPathHistory(w http.ResponseWriter, r *http.Request) error {
	limit, err := intParam(r, "limit", 100)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	cursor, err := parseBGPASPathHistoryArgs(bgpASPathHistoryArgs{ID: r.PathValue("id"), From: q.Get("from"), To: q.Get("to"),
		Source: q.Get("source"), Vantage: q.Get("vantage"), Cursor: q.Get("cursor"), Limit: limit})
	if err != nil {
		return err
	}
	page, err := s.readBGPASPathHistory(r.Context(), auth.PrincipalFrom(r.Context()), cursor, false)
	if err != nil {
		return bgpASPathHistoryError(err)
	}
	writeJSON(w, http.StatusOK, page)
	return nil
}

func (s *Server) readBGPASPathHistory(ctx context.Context, actor *auth.Principal, cursor bgpASPathHistoryCursor, native bool) (bgpASPathHistoryPage, error) {
	none := bgpASPathHistoryPage{}
	if s.pool == nil {
		return none, apierror.Unavailable("AS path history storage is unavailable")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if s.requireMFA && !actor.MFASatisfied {
		return none, apierror.Forbidden("multi-factor authentication required")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return none, apierror.Unavailable("AS path history admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	if s.fairnessGate != nil {
		release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
		if err != nil {
			return none, err
		}
		defer release()
	}
	profile := store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.MemoryBytes / 2, StateBytes: budget.MemoryBytes}
	out := none
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
		out, err = s.loadBGPASPathHistoryInScope(checked, sc, principal, cursor, profile)
		return err
	})
	return out, err
}

func (s *Server) loadBGPASPathHistoryInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, cursor bgpASPathHistoryCursor,
	profile store.BGPRoutingBudget) (bgpASPathHistoryPage, error) {
	none := bgpASPathHistoryPage{}
	monitor, err := store.BGPVisibilityMonitorInScope(ctx, sc, cursor.Query.Monitor)
	if err != nil {
		return none, err
	}
	if cursor.Query.SourceKind == "" && !actor.Has(ai.PermEntitiesRead) {
		cursor.Query.SourceKind = "public_mrt"
	}
	records, more, err := store.BGPASPathHistoryInScope(ctx, sc, cursor.Query, profile)
	if err != nil {
		return none, err
	}
	out := bgpASPathHistoryPage{Monitor: monitor, Items: []bgpASPathHistoryRow{}, Coverage: "no_retained_points", EffectiveLimit: cursor.Query.Limit}
	authorize := s.routingChangeAuthorizer(actor)
	authorizeChange := s.routingChangeAuthorizer(actor, permChangeRead)
	linkIncidents := actor.Has(permIncidentRead) && s.authorize(ctx, actor, permIncidentRead, auth.RBACGlobal, nil) == nil
	remainingLinks := profile.MemoryBytes / 1024
	window := s.cfg.ChangeCorrelationWindow
	if window <= 0 {
		window = 24 * time.Hour
	}
	for _, record := range records {
		row, err := loadBGPASPathHistoryRecord(ctx, sc, monitor.Prefix, record, profile, authorize, authorizeChange)
		if err != nil {
			return none, err
		}
		if linkIncidents {
			row.Incidents, err = store.BGPASPathIncidentsInScope(ctx, sc, monitor, record, row.PublicSource, window, incidentCandidateLimit)
			if err != nil {
				return none, err
			}
			remainingLinks -= int64(len(row.Incidents))
			if remainingLinks < 0 {
				return none, store.ErrBGPRoutingBudget
			}
		}
		out.Items = append(out.Items, row)
	}
	if len(out.Items) != 0 {
		out.Coverage = "retained_points"
	}
	if more {
		last := records[len(records)-1].BGPASPathHistoryPosition
		cursor.Query.After = &last
		body, err := json.Marshal(cursor)
		if err != nil {
			return none, err
		}
		out.NextCursor = base64.RawURLEncoding.EncodeToString(body)
	}
	return out, ctx.Err()
}

func loadBGPASPathHistoryRecord(ctx context.Context, sc tenancy.Scope, prefix netip.Prefix, record store.BGPASPathHistoryRecord, profile store.BGPRoutingBudget,
	authorize, authorizeChange store.RoutingChangeAuthorizer) (bgpASPathHistoryRow, error) {
	row := bgpASPathHistoryRow{BGPASPathHistoryRecord: record}
	switch record.SourceKind {
	case "router_bmp":
		source, err := store.VerifyBGPASPathHistorySourceInScope(ctx, sc, prefix, record, profile,
			func(ctx context.Context, sc tenancy.Scope, source store.BGPRoutingSource, event change.Event) error {
				if err := authorize(ctx, sc, source, event); err != nil {
					return err
				}
				if row.ChangeEventID != "" && authorizeChange(ctx, sc, source, event) != nil {
					row.ChangeEventID = ""
				}
				return ctx.Err()
			})
		if err != nil {
			return row, err
		}
		row.RouterView, row.OriginalClock = source.View, &source.ObservedAt
	case "public_mrt":
		var original store.BGPASPathPublicSource
		if err := json.Unmarshal(record.Original, &original); err != nil {
			return row, err
		}
		row.PublicSource = &original
		observed := time.Unix(0, original.ObservedUnixNanos).UTC()
		row.OriginalClock = &observed
	default:
		return row, change.ErrRouteReference
	}
	for _, path := range []struct {
		raw    json.RawMessage
		target **bgpASPathStage
	}{{record.Previous, &row.Previous}, {record.Current, &row.Current}} {
		if len(path.raw) == 0 {
			continue
		}
		var stage bgpASPathStage
		if err := json.Unmarshal(path.raw, &stage); err != nil {
			return row, err
		}
		if stage.Segments == nil {
			stage.Segments = []bgp.ASPathSegment{}
		}
		stage.Facts = bgp.SummarizeASPath(stage.Segments)
		*path.target = &stage
	}
	if row.Previous != nil && row.Current != nil {
		changes := bgp.CompareASPaths(row.Previous.Segments, row.Current.Segments)
		row.Changes = &changes
	}
	return row, nil
}

func bgpASPathHistoryError(err error) error {
	switch {
	case errors.Is(err, store.ErrBGPRoutingBudget):
		return apierror.RateLimited("the complete AS path page exceeds resource admission")
	case errors.Is(err, store.ErrBGPRoutingSourceUnavailable), errors.Is(err, pgx.ErrNoRows), errors.Is(err, change.ErrRouteReference):
		return apierror.NotFound("the original AS path source is unavailable")
	default:
		return bgpVisibilityAPIError(err)
	}
}
