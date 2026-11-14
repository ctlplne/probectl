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
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type changeTimelineCursor struct {
	Version int       `json:"version"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Before  time.Time `json:"before"`
	ID      string    `json:"id"`
}

func decodeChangeTimelineCursor(encoded string) (changeTimelineCursor, error) {
	var cursor changeTimelineCursor
	if len(encoded) > 2048 {
		return cursor, apierror.BadRequest("invalid change cursor")
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || json.Unmarshal(body, &cursor) != nil || cursor.Version != 1 || cursor.From.IsZero() || !cursor.To.After(cursor.From) || cursor.Before.Before(cursor.From) || !cursor.Before.Before(cursor.To) {
		return cursor, apierror.BadRequest("invalid change cursor")
	}
	id := cursor.ID
	const prefix = "device-config:"
	if len(id) > len(prefix) && id[:len(prefix)] == prefix {
		id = id[len(prefix):]
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return cursor, apierror.BadRequest("invalid change cursor")
	}
	return cursor, nil
}

func (s *Server) handleListChanges(w http.ResponseWriter, r *http.Request) error {
	scope := s.configEvidenceForRequest(r, permChangeRead)
	actor := scope.actor
	if actor == nil {
		return apierror.Unauthorized("authentication required")
	}
	budget := flowstore.ExplorerOperationBudget(r.Context(), s.flowStore)
	if err := budget.Validate(); err != nil {
		return apierror.Unavailable("change query resource admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget.ExecutionLimit)
	defer cancel()
	r = r.WithContext(ctx)
	if s.fairnessGate != nil {
		release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
		if err != nil {
			return err
		}
		defer release()
	}
	query := r.URL.Query()
	cursor := changeTimelineCursor{Version: 1, From: time.Unix(0, 0).UTC(), To: time.Now().UTC()}
	if encoded := query.Get("cursor"); encoded != "" {
		var err error
		cursor, err = decodeChangeTimelineCursor(encoded)
		if err != nil {
			return err
		}
	} else {
		for key, target := range map[string]*time.Time{"from": &cursor.From, "to": &cursor.To} {
			if value := query.Get(key); value != "" {
				parsed, err := time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return apierror.BadRequest("invalid change window")
				}
				*target = parsed.UTC()
			}
		}
		if cursor.From.IsZero() || !cursor.To.After(cursor.From) {
			return apierror.BadRequest("invalid change window")
		}
	}
	limit := changeListLimit
	if value := query.Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			return apierror.BadRequest("invalid change page size")
		}
		limit = parsed
	}
	memory := budget.MemoryBytes / 8
	if memory < 4096 || int64(limit) >= memory/2048 {
		return apierror.TooLarge("change page exceeds configured resource admission")
	}
	var page store.ChangeTimelinePage
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		page, err = (store.ChangeEvents{}).TimelinePageInScope(ctx, sc, cursor.From, cursor.To, cursor.Before, cursor.ID, limit, memory)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrClientReportBudget) {
			return apierror.TooLarge("change page exceeds configured resource admission")
		}
		return err
	}
	tenant, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	for _, event := range page.Events {
		if err := scope.retain(event); err != nil {
			return err
		}
	}
	next := ""
	if page.More {
		last := page.Events[len(page.Events)-1]
		cursor.Before, cursor.ID = last.OccurredAt, last.ID
		body, err := json.Marshal(cursor)
		if err != nil {
			return err
		}
		next = base64.RawURLEncoding.EncodeToString(body)
	}
	body, err := json.Marshal(map[string]any{
		"items": page.Events, "change_ingest_configured": s.changeIngestConfigured(tenant),
		"config_archive_running": s.deviceOps != nil, "effective_limit": limit, "truncated": page.More, "next_cursor": next,
	})
	if err != nil {
		return err
	}
	if err := scope.check(r.Context()); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, json.RawMessage(body))
	return nil
}
