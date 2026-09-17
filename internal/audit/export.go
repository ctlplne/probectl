// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Sink is the audit export hook: a destination that receives audit events for
// external delivery (S32 SIEM connectors — syslog/CEF/OTLP — implement it). It is
// the stable contract S32 consumes; probectl ships the pull-based reader (List)
// below, and S32 adds push sinks on top without changing this interface.
//
// A Sink must treat delivery as best-effort and idempotent on Event.Seq: it may
// be re-invoked for the same event after a restart, and it must never block the
// audited transaction (export happens out of band of TenantAppend).
type Sink interface {
	// Export delivers one audit event. The streamKey is the tenant id for the
	// tenant stream, or "provider" for the provider/break-glass stream.
	Export(ctx context.Context, streamKey string, ev Event) error
}

// DefaultExportPageSize / MaxExportPageSize bound a pull-export page.
const (
	DefaultExportPageSize = 100
	MaxExportPageSize     = 1000
)

// Filter narrows tenant audit reads by the operator-facing fields auditors use
// most often. Values are contains matches, executed inside the tenant RLS scope.
type Filter struct {
	Actor  string
	Action string
	Target string
}

// TenantExportRow is the format-version-1 PostgreSQL portability shape for one
// tenant audit row. ID and TenantID are storage identity fields that the audit
// API's Event intentionally omits; embedding Event preserves the remaining
// seq/actor/action/target/data/chain/timestamp fields.
type TenantExportRow struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Event
}

// List returns a page of the calling tenant's audit events with seq greater than
// afterSeq, in ascending order (the natural export cursor). RLS confines it to
// the tenant. A non-positive limit uses DefaultExportPageSize; limit is capped at
// MaxExportPageSize. The returned events carry the stored chain fields so a
// consumer can re-verify or forward them.
func List(ctx context.Context, s tenancy.Scope, afterSeq int64, limit int) ([]Event, error) {
	return ListFiltered(ctx, s, afterSeq, limit, Filter{})
}

// ListFiltered is List plus optional contains filters on actor/action/target.
// Filtering remains server-side and parameterized so the browser never becomes
// the authority for audit scope, and RLS still applies before any rows return.
func ListFiltered(ctx context.Context, s tenancy.Scope, afterSeq int64, limit int, filter Filter) ([]Event, error) {
	if limit <= 0 {
		limit = DefaultExportPageSize
	}
	if limit > MaxExportPageSize {
		limit = MaxExportPageSize
	}
	filter.Actor = normalizeFilter(filter.Actor)
	filter.Action = normalizeFilter(filter.Action)
	filter.Target = normalizeFilter(filter.Target)
	erased, err := subjectErasureHashes(ctx, s)
	if err != nil {
		return nil, err
	}
	rows, err := s.Q.Query(ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash, created_at
		   FROM audit_events
		  WHERE seq > $1
		    AND ($3 = '' OR actor ILIKE '%' || $3 || '%')
		    AND ($4 = '' OR action ILIKE '%' || $4 || '%')
		    AND ($5 = '' OR target ILIKE '%' || $5 || '%')
		  ORDER BY seq
		  LIMIT $2`, afterSeq, limit, filter.Actor, filter.Action, filter.Target)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	out := []Event{}
	for rows.Next() {
		var (
			ev        Event
			dataBytes []byte
		)
		if err := rows.Scan(&ev.Seq, &ev.Actor, &ev.Action, &ev.Target, &dataBytes, &ev.PrevHash, &ev.Hash, &ev.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(dataBytes, &ev.Data); err != nil {
			return nil, fmt.Errorf("seq %d: decode data: %w", ev.Seq, err)
		}
		out = append(out, projectErasedSubjects(ev, s.Tenant.String(), erased))
	}
	return out, rows.Err()
}

// ListExportRows returns format-version-1 portability rows after afterSeq with
// the canonical subject-erasure projection applied. The advisory transaction
// lock prevents retention or appends from changing the stream between pages;
// callers that page in one tenancy.Scope transaction keep that lock until the
// bundle's audit read finishes.
func ListExportRows(
	ctx context.Context,
	s tenancy.Scope,
	afterSeq int64,
	limit int,
) ([]TenantExportRow, error) {
	if limit <= 0 {
		limit = DefaultExportPageSize
	}
	if limit > MaxExportPageSize {
		limit = MaxExportPageSize
	}
	if err := lockTenantStream(ctx, s.Q, s.Tenant.String()); err != nil {
		return nil, fmt.Errorf("lock audit export chain: %w", err)
	}
	erased, err := subjectErasureHashes(ctx, s)
	if err != nil {
		return nil, err
	}
	rows, err := s.Q.Query(
		ctx,
		`SELECT id::text,
		        tenant_id::text,
		        seq,
		        actor,
		        action,
		        target,
		        data,
		        prev_hash,
		        hash,
		        created_at
		   FROM audit_events
		  WHERE seq > $1
		  ORDER BY seq
		  LIMIT $2`,
		afterSeq,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit export rows: %w", err)
	}
	defer rows.Close()

	out := make([]TenantExportRow, 0, limit)
	for rows.Next() {
		var (
			row       TenantExportRow
			dataBytes []byte
		)
		if err := rows.Scan(
			&row.ID,
			&row.TenantID,
			&row.Seq,
			&row.Actor,
			&row.Action,
			&row.Target,
			&dataBytes,
			&row.PrevHash,
			&row.Hash,
			&row.CreatedAt,
		); err != nil {
			return nil, err
		}
		if row.TenantID != s.Tenant.String() {
			return nil, fmt.Errorf("audit export row escaped tenant scope")
		}
		if err := json.Unmarshal(dataBytes, &row.Data); err != nil {
			return nil, fmt.Errorf("seq %d: decode export data: %w", row.Seq, err)
		}
		row.Event = projectErasedSubjects(
			row.Event,
			s.Tenant.String(),
			erased,
		)
		out = append(out, row)
	}
	return out, rows.Err()
}

func normalizeFilter(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 256 {
		return v[:256]
	}
	return v
}

// Drain reads the tenant's audit events after afterSeq and pushes each to sink,
// returning the highest seq delivered (the new cursor). It is the building block
// a scheduled SIEM exporter (S32) uses: read a page, deliver, advance the cursor.
// Delivery is sequential and stops at the first sink error so the cursor never
// skips an undelivered event.
func Drain(ctx context.Context, s tenancy.Scope, sink Sink, afterSeq int64, limit int) (int64, error) {
	if afterSeq < 0 {
		return afterSeq, fmt.Errorf("audit export cursor must be non-negative")
	}
	head, haveHead, err := readTenantStreamHead(ctx, s.Q, s.Tenant.String())
	if err != nil {
		return afterSeq, err
	}
	if haveHead {
		if afterSeq < head.PrunedSeq {
			return afterSeq, fmt.Errorf(
				"audit export cursor %d is behind tenant prune anchor %d",
				afterSeq,
				head.PrunedSeq,
			)
		}
		if afterSeq > head.HeadSeq {
			return afterSeq, fmt.Errorf(
				"audit export cursor %d is above tenant durable head %d",
				afterSeq,
				head.HeadSeq,
			)
		}
	}
	events, err := List(ctx, s, afterSeq, limit)
	if err != nil {
		return afterSeq, err
	}
	if haveHead && head.HeadSeq > afterSeq {
		if len(events) == 0 {
			return afterSeq, fmt.Errorf(
				"tenant durable head %d has no row after audit export cursor %d",
				head.HeadSeq,
				afterSeq,
			)
		}
		if events[0].Seq != afterSeq+1 {
			return afterSeq, fmt.Errorf(
				"audit export sequence gap after cursor %d (next row is %d)",
				afterSeq,
				events[0].Seq,
			)
		}
	}
	cursor := afterSeq
	for _, ev := range events {
		if err := sink.Export(ctx, s.Tenant.String(), ev); err != nil {
			return cursor, fmt.Errorf("export seq %d: %w", ev.Seq, err)
		}
		cursor = ev.Seq
	}
	return cursor, nil
}

// ProviderListFiltered pages the provider/break-glass audit stream oldest-first
// after afterSeq (DPR-037). It is the read side of ProviderAppend: the stream
// always existed as WORM segments and SIEM export, but an MSP operator had no
// in-product way to see what their own plane recorded. No subject-erasure
// projection applies — actors here are provider operators, not tenant users.
func ProviderListFiltered(ctx context.Context, q tenancy.Querier, afterSeq int64, limit int, filter Filter) ([]Event, error) {
	return providerList(ctx, q, afterSeq, limit, filter, false)
}

// ProviderListRecent pages the provider audit stream newest-first before
// beforeSeq (0 = from the head), which is what an activity view wants.
func ProviderListRecent(ctx context.Context, q tenancy.Querier, beforeSeq int64, limit int, filter Filter) ([]Event, error) {
	return providerList(ctx, q, beforeSeq, limit, filter, true)
}

func providerList(ctx context.Context, q tenancy.Querier, cursor int64, limit int, filter Filter, newestFirst bool) ([]Event, error) {
	if q == nil {
		return nil, errors.New("audit: provider stream querier is nil")
	}
	if limit <= 0 {
		limit = DefaultExportPageSize
	}
	if limit > MaxExportPageSize {
		limit = MaxExportPageSize
	}
	filter.Actor = normalizeFilter(filter.Actor)
	filter.Action = normalizeFilter(filter.Action)
	filter.Target = normalizeFilter(filter.Target)
	where, order := `seq > $1`, `seq`
	if newestFirst {
		order = `seq DESC`
		if cursor > 0 {
			where = `seq < $1`
		} else {
			where = `$1 = 0`
		}
	}
	rows, err := q.Query(ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash, created_at
		   FROM provider_audit_events
		  WHERE `+where+`
		    AND ($3 = '' OR actor ILIKE '%' || $3 || '%')
		    AND ($4 = '' OR action ILIKE '%' || $4 || '%')
		    AND ($5 = '' OR target ILIKE '%' || $5 || '%')
		  ORDER BY `+order+`
		  LIMIT $2`, cursor, limit, filter.Actor, filter.Action, filter.Target)
	if err != nil {
		return nil, fmt.Errorf("list provider audit events: %w", err)
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var (
			ev        Event
			dataBytes []byte
		)
		if err := rows.Scan(&ev.Seq, &ev.Actor, &ev.Action, &ev.Target, &dataBytes, &ev.PrevHash, &ev.Hash, &ev.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(dataBytes, &ev.Data); err != nil {
			return nil, fmt.Errorf("provider seq %d: decode data: %w", ev.Seq, err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
