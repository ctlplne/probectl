package audit

import (
	"context"
	"encoding/json"
	"fmt"

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

// List returns a page of the calling tenant's audit events with seq greater than
// afterSeq, in ascending order (the natural export cursor). RLS confines it to
// the tenant. A non-positive limit uses DefaultExportPageSize; limit is capped at
// MaxExportPageSize. The returned events carry the stored chain fields so a
// consumer can re-verify or forward them.
func List(ctx context.Context, s tenancy.Scope, afterSeq int64, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = DefaultExportPageSize
	}
	if limit > MaxExportPageSize {
		limit = MaxExportPageSize
	}
	rows, err := s.Q.Query(ctx,
		`SELECT seq, actor, action, target, data, prev_hash, hash, created_at
		   FROM audit_events
		  WHERE seq > $1
		  ORDER BY seq
		  LIMIT $2`, afterSeq, limit)
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
		out = append(out, ev)
	}
	return out, rows.Err()
}

// Drain reads the tenant's audit events after afterSeq and pushes each to sink,
// returning the highest seq delivered (the new cursor). It is the building block
// a scheduled SIEM exporter (S32) uses: read a page, deliver, advance the cursor.
// Delivery is sequential and stops at the first sink error so the cursor never
// skips an undelivered event.
func Drain(ctx context.Context, s tenancy.Scope, sink Sink, afterSeq int64, limit int) (int64, error) {
	events, err := List(ctx, s, afterSeq, limit)
	if err != nil {
		return afterSeq, err
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
