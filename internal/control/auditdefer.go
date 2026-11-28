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
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Read auditing during a failover (DPR-101).
//
// Every sensitive read appends an access.read event before it is served.
// While the writer endpoint is a read-only standby (or the writer pool is
// fenced on a stale ex-primary) that append is refused, and the request used
// to fail with 500 — so "reads keep serving during a failover" held for
// nothing that is audited. A sensitive read can serve after its audit event
// enters a bounded per-replica queue. Once writes are usable, each replayed
// event carries deferred_at and the reason. A full queue, export, operational
// action or mutation returns 503 writer_unavailable with Retry-After.

const (
	deferredAuditMaxQueue     = 10000
	deferredAuditFlushEvery   = 5 * time.Second
	metricAuditDeferredTotal  = "probectl_audit_deferred_total"
	metricAuditDeferredDrops  = "probectl_audit_deferred_dropped_total"
	metricAuditDeferredFlushd = "probectl_audit_deferred_flushed_total"
)

// deferredAuditEvent is one access.read event waiting for a writable database.
type deferredAuditEvent struct {
	tenantID, actor, action, target string
	data                            map[string]any
	at                              time.Time
}

// deferredAuditQueue is a bounded FIFO of deferred audit events (per replica).
type deferredAuditQueue struct {
	mu      sync.Mutex
	flushMu sync.Mutex
	events  []deferredAuditEvent
	dropped uint64
}

func (q *deferredAuditQueue) push(e deferredAuditEvent) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.events) >= deferredAuditMaxQueue {
		q.dropped++
		return false
	}
	q.events = append(q.events, e)
	return true
}

func (q *deferredAuditQueue) pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.events)
}

// first keeps the oldest event in the queue until its durable append succeeds.
func (q *deferredAuditQueue) first() (deferredAuditEvent, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.events) == 0 {
		return deferredAuditEvent{}, false
	}
	return q.events[0], true
}

// removeFirst is called only by the active flush after a successful append.
func (q *deferredAuditQueue) removeFirst() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events[0] = deferredAuditEvent{}
	q.events = q.events[1:]
}

// writesRefused reports whether err is the database refusing a write because
// the session is read-only (a hot standby, or the fenced writer pool) or the
// tenant writer fence: the conditions under which reads must still serve.
func writesRefused(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, tenancy.ErrTenantWritesFenced) {
		return true
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "25006" { // read_only_sql_transaction
		return true
	}
	return false
}

// appendRouteAudit writes a wrapped route's access event: the injectable seam
// in tests, the tenant chain in production.
func (s *Server) appendRouteAudit(r *http.Request, action, target string, data map[string]any) error {
	if s.routeAudit != nil {
		return s.routeAudit(r, action, target, data)
	}
	if s.pool == nil {
		return nil
	}
	return s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, action, target, data)
	})
}

// deferRouteAudit reports whether a sensitive read's event was admitted for
// replay once the database accepts writes again.
func (s *Server) deferRouteAudit(r *http.Request, action, target string, data map[string]any) bool {
	tenantID := ""
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		tenantID = p.TenantID
	}
	ev := deferredAuditEvent{tenantID: tenantID, actor: auditActor(r), action: action, target: target, data: data, at: time.Now().UTC()}
	if s.deferredAudit.push(ev) {
		s.metrics.Counter(metricAuditDeferredTotal, "").Inc()
		deferredAuditLog.Log(s.log, "audit event deferred while the writer is fenced",
			[]string{"audit-deferred", action}, "action", action, "target", target)
		return true
	}
	s.metrics.Counter(metricAuditDeferredDrops, "").Inc()
	s.log.Error("sensitive read refused because the deferred audit queue is full",
		"action", action, "target", target, "queue", deferredAuditMaxQueue)
	return false
}

// deferredAuditLog folds repeated deferrals into one line per action per
// minute (DPR-074 shape): a failover deferring thousands of reads must not
// flood the log.
var deferredAuditLog = newRejectionLogger(time.Minute)

// FlushDeferredAudit replays queued events in order until the queue is empty
// or the database refuses again. It is safe to call concurrently with new
// deferrals; it returns the number of events appended.
func (s *Server) FlushDeferredAudit(ctx context.Context) int {
	s.deferredAudit.flushMu.Lock()
	defer s.deferredAudit.flushMu.Unlock()
	flushed := 0
	for {
		ev, ok := s.deferredAudit.first()
		if !ok {
			return flushed
		}
		data := make(map[string]any, len(ev.data)+2)
		for k, v := range ev.data {
			data[k] = v
		}
		data["deferred_at"] = ev.at.Format(time.RFC3339)
		data["deferred_reason"] = "writer fenced during failover"
		var err error
		if s.routeAuditReplay != nil {
			err = s.routeAuditReplay(ctx, ev.tenantID, ev.actor, ev.action, ev.target, data)
		} else if s.pool != nil && ev.tenantID != "" {
			err = s.inTenantID(ctx, ev.tenantID, func(ctx context.Context, sc tenancy.Scope) error {
				_, aerr := audit.TenantAppend(ctx, sc, ev.actor, ev.action, ev.target, data)
				return aerr
			})
		}
		if err != nil {
			return flushed
		}
		s.deferredAudit.removeFirst()
		flushed++
		s.metrics.Counter(metricAuditDeferredFlushd, "").Inc()
	}
}

// RunDeferredAudit drains the queue on a ticker while writes are usable.
func (s *Server) RunDeferredAudit(ctx context.Context) {
	t := time.NewTicker(deferredAuditFlushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.deferredAudit.pending() == 0 {
				continue
			}
			if s.cluster != nil {
				if ok, _ := s.cluster.WriterUsable(); !ok {
					continue
				}
			}
			if n := s.FlushDeferredAudit(ctx); n > 0 {
				s.log.Info("deferred audit events appended after the failover", "count", n, "pending", s.deferredAudit.pending())
			}
		}
	}
}

// auditWritesRefused returns 503 with Retry-After when a required audit event
// cannot be written or queued.
func auditWritesRefused(w http.ResponseWriter) error {
	w.Header().Set("Retry-After", "2")
	return apierror.Unavailable("audit is required for this action and the audit store refuses writes (writer fenced during failover)").WithCode("writer_unavailable")
}
