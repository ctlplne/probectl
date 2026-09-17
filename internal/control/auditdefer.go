// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
// nothing that is audited. A sensitive read now serves and its audit event is
// deferred in a bounded per-replica queue that drains once writes are usable
// again (each replayed event carries deferred_at and the reason); exports,
// operational actions and mutations stay fail-closed but answer an honest
// 503 writer_unavailable with Retry-After instead of a 500.

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

// pop removes and returns the oldest event; ok=false when empty.
func (q *deferredAuditQueue) pop() (deferredAuditEvent, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.events) == 0 {
		return deferredAuditEvent{}, false
	}
	e := q.events[0]
	q.events = q.events[1:]
	return e, true
}

// unshift puts an event back at the head after a failed replay.
func (q *deferredAuditQueue) unshift(e deferredAuditEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events = append([]deferredAuditEvent{e}, q.events...)
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

// deferRouteAudit queues a sensitive read's audit event for replay once the
// database accepts writes again. Best effort and bounded: overflow is counted
// and logged loudly, never silent.
func (s *Server) deferRouteAudit(r *http.Request, action, target string, data map[string]any) {
	tenantID := ""
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		tenantID = p.TenantID
	}
	ev := deferredAuditEvent{tenantID: tenantID, actor: auditActor(r), action: action, target: target, data: data, at: time.Now().UTC()}
	if s.deferredAudit.push(ev) {
		s.metrics.Counter(metricAuditDeferredTotal, "").Inc()
		deferredAuditLog.Log(s.log, "audit event deferred: the database refuses writes (failover in progress); the read was served and the event will be appended once writes return",
			[]string{"audit-deferred", action}, "action", action, "target", target)
		return
	}
	s.metrics.Counter(metricAuditDeferredDrops, "").Inc()
	s.log.Error("audit event DROPPED: the deferred-audit queue is full while the database refuses writes",
		"action", action, "target", target, "queue", deferredAuditMaxQueue)
}

// deferredAuditLog folds repeated deferrals into one line per action per
// minute (DPR-074 shape): a failover deferring thousands of reads must not
// flood the log.
var deferredAuditLog = newRejectionLogger(time.Minute)

// FlushDeferredAudit replays queued events in order until the queue is empty
// or the database refuses again. It is safe to call concurrently with new
// deferrals; it returns the number of events appended.
func (s *Server) FlushDeferredAudit(ctx context.Context) int {
	flushed := 0
	for {
		ev, ok := s.deferredAudit.pop()
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
			s.deferredAudit.unshift(ev)
			return flushed
		}
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

// auditWritesRefused is the fail-closed answer for an export, operational
// action or mutation whose audit event cannot be written: honest 503 with a
// Retry-After, never a 500.
func auditWritesRefused(w http.ResponseWriter) error {
	w.Header().Set("Retry-After", "2")
	return apierror.Unavailable("audit is required for this action and the audit store refuses writes (writer fenced during failover)").WithCode("writer_unavailable")
}
