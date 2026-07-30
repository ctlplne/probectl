// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
