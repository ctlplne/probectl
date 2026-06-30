// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/change"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// ChangeEvents is the tenant-scoped change-event repository (S29, F39). RLS
// confines every row to the caller's tenant (F50), so the change timeline and the
// change<->incident correlation never cross tenants.
type ChangeEvents struct{}

const changeCols = `id::text, tenant_id::text, source, kind, title, summary, target, prefix,
	actor, ref, url, attributes, occurred_at, received_at`

func scanChange(row interface{ Scan(...any) error }, c *change.Event) error {
	var kind string
	var attrs []byte
	if err := row.Scan(&c.ID, &c.TenantID, &c.Source, &kind, &c.Title, &c.Summary, &c.Target,
		&c.Prefix, &c.Actor, &c.Ref, &c.URL, &attrs, &c.OccurredAt, &c.ReceivedAt); err != nil {
		return err
	}
	c.Kind = change.Kind(kind)
	if len(attrs) > 0 {
		if err := json.Unmarshal(attrs, &c.Attributes); err != nil {
			return fmt.Errorf("store: decode change %s attributes: %w", c.ID, err)
		}
	}
	return nil
}

// Create inserts a normalized change event. The tenant comes from the scope (the
// verified webhook credential), never the event's TenantID field.
func (ChangeEvents) Create(ctx context.Context, s tenancy.Scope, ev change.Event) (*change.Event, error) {
	attrs, err := json.Marshal(ev.Attributes)
	if err != nil {
		attrs = []byte("{}")
	}
	var out change.Event
	if err := scanChange(s.Q.QueryRow(ctx,
		`INSERT INTO change_events
		   (tenant_id, source, kind, title, summary, target, prefix, actor, ref, url, attributes, occurred_at, received_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,now())
		 RETURNING `+changeCols,
		s.Tenant.String(), ev.Source, string(ev.Kind), ev.Title, ev.Summary, ev.Target, ev.Prefix,
		ev.Actor, ev.Ref, ev.URL, attrs, ev.OccurredAt), &out); err != nil {
		return nil, mapWriteErr("change_event", err)
	}
	return &out, nil
}

// List returns the tenant's change timeline, newest first.
func (ChangeEvents) List(ctx context.Context, s tenancy.Scope, limit int) ([]change.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	return queryChanges(ctx, s, `SELECT `+changeCols+`
		FROM change_events ORDER BY occurred_at DESC LIMIT $1`, limit)
}

// Since returns the tenant's change events at/after `since`, newest first — the
// correlation candidate set for an incident's lookback window.
func (ChangeEvents) Since(ctx context.Context, s tenancy.Scope, since time.Time, limit int) ([]change.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	return queryChanges(ctx, s, `SELECT `+changeCols+`
		FROM change_events WHERE occurred_at >= $1 ORDER BY occurred_at DESC LIMIT $2`, since, limit)
}

// Between returns the tenant's change events inside an inclusive time window,
// newest first. AI/RCA evidence uses this instead of Since so a future-dated
// change cannot appear in an answer for a bounded question window.
func (ChangeEvents) Between(ctx context.Context, s tenancy.Scope, start, end time.Time, limit int) ([]change.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	if end.IsZero() {
		end = time.Now().UTC()
	}
	if end.Before(start) {
		return []change.Event{}, nil
	}
	return queryChanges(ctx, s, `SELECT `+changeCols+`
		FROM change_events
		WHERE occurred_at >= $1 AND occurred_at <= $2
		ORDER BY occurred_at DESC LIMIT $3`, start, end, limit)
}

func queryChanges(ctx context.Context, s tenancy.Scope, sql string, args ...any) ([]change.Event, error) {
	rows, err := s.Q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []change.Event{}
	for rows.Next() {
		var c change.Event
		if err := scanChange(rows, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
