// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ChangeEvents is the tenant-scoped change-event repository (S29, F39). RLS
// confines every row to the caller's tenant (F50), so the change timeline and the
// change<->incident correlation never cross tenants.
type ChangeEvents struct{}

// WebhookDelivery is the idempotency receipt for one signed change-webhook
// delivery. It deliberately stores only routing metadata, never the untrusted
// webhook payload. BodyFingerprint is a server-computed hash of the exact
// authenticated body (the bytes the HMAC signs); it is the replay key that
// survives a rotated delivery-id header (AUTHZ-19). Empty leaves the column NULL
// (the legacy delivery-id-only behavior).
type WebhookDelivery struct {
	CredentialID    string
	Provider        string
	DeliveryID      string
	EventCount      int
	BodyFingerprint string
}

// WebhookDeliveries records signed webhook receipts before downstream mutation.
// Two keys mark a delivery as already-seen, so a replay returns success without
// appending duplicate change or audit rows: the client-supplied provider
// delivery id (tenant + credential + provider + delivery id, the primary key),
// AND the server-computed body fingerprint (tenant + credential + provider +
// fingerprint), which catches a replay that rotates only the delivery-id header
// (AUTHZ-19).
type WebhookDeliveries struct{}

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

// Record claims a delivery for this tenant. It returns true only for the first
// sighting; duplicate sightings atomically increment duplicate_count and return
// false so callers can treat replay as an idempotent no-op.
//
// A delivery is a duplicate when EITHER its server-computed body fingerprint OR
// its provider delivery id was already seen for this (tenant, credential,
// provider). The fingerprint is checked first (AUTHZ-19): it is derived from the
// exact bytes the HMAC signed, so a replay that rotates only the client-supplied
// delivery-id header is still caught. The whole function runs inside the caller's
// tenant transaction (tenancy.InTenant), and the partial unique index on the
// fingerprint makes even a concurrent double-submit fail closed rather than store
// a second row.
func (WebhookDeliveries) Record(ctx context.Context, s tenancy.Scope, d WebhookDelivery) (bool, error) {
	if d.BodyFingerprint != "" {
		// A prior sighting of this authenticated body — regardless of its
		// delivery-id header — is an idempotent duplicate: bump the original
		// receipt and report not-fresh without writing a new row.
		var bumped bool
		err := s.Q.QueryRow(ctx,
			`UPDATE webhook_deliveries
			    SET last_seen_at = now(),
			        duplicate_count = duplicate_count + 1
			  WHERE tenant_id = $1 AND credential_id = $2 AND provider = $3
			    AND body_fingerprint = $4
			 RETURNING true`,
			s.Tenant.String(), d.CredentialID, d.Provider, d.BodyFingerprint).Scan(&bumped)
		switch {
		case err == nil && bumped:
			return false, nil
		case errors.Is(err, pgx.ErrNoRows):
			// First sighting of this body — fall through to the insert below.
		default:
			return false, mapWriteErr("webhook_delivery", err)
		}
	}

	var fingerprint any
	if d.BodyFingerprint != "" {
		fingerprint = d.BodyFingerprint
	}
	var fresh bool
	err := s.Q.QueryRow(ctx,
		`INSERT INTO webhook_deliveries
		   (tenant_id, credential_id, provider, delivery_id, event_count, body_fingerprint, first_seen_at, last_seen_at, duplicate_count)
		 VALUES ($1,$2,$3,$4,$5,$6,now(),now(),0)
		 ON CONFLICT (tenant_id, credential_id, provider, delivery_id)
		   DO UPDATE SET last_seen_at = now(),
		                 duplicate_count = webhook_deliveries.duplicate_count + 1
		 RETURNING duplicate_count = 0`,
		s.Tenant.String(), d.CredentialID, d.Provider, d.DeliveryID, d.EventCount, fingerprint).Scan(&fresh)
	if err != nil {
		return false, mapWriteErr("webhook_delivery", err)
	}
	return fresh, nil
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
