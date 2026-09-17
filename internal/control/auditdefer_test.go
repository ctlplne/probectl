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
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func readOnlyRefusal() error {
	return &pgconn.PgError{Code: "25006", Message: "cannot execute INSERT in a read-only transaction"}
}

// TestSensitiveReadsServeAndDeferTheirAuditOnAReadOnlyDatabase (DPR-101): on
// the lab every audited read answered 500 while the writer endpoint pointed at
// the read-only standby, because the access.read append was refused and the
// wrapper failed the request. A sensitive read must serve, keep its event in
// the deferred queue and replay it — with the deferral stamped — once writes
// return; anything that exports, operates or mutates stays fail-closed with a
// retryable 503, and a non-read-only failure is still an error.
func TestSensitiveReadsServeAndDeferTheirAuditOnAReadOnlyDatabase(t *testing.T) {
	srv := testServer(nil)
	srv.routeAudit = func(*http.Request, string, string, map[string]any) error { return readOnlyRefusal() }
	served := 0
	next := func(w http.ResponseWriter, _ *http.Request) error {
		served++
		w.WriteHeader(http.StatusOK)
		return nil
	}
	read := srv.auditRoute(apiRoute{Method: http.MethodGet, Pattern: "/v1/tests"}, auditWrapped(auditFacetSensitiveRead), next)
	rec := httptest.NewRecorder()
	if err := read(rec, httptest.NewRequest(http.MethodGet, "/v1/tests", nil)); err != nil {
		t.Fatalf("a sensitive read must serve while the database is read-only, got %v", err)
	}
	if served != 1 || srv.deferredAudit.pending() != 1 {
		t.Fatalf("served=%d pending=%d, want 1/1", served, srv.deferredAudit.pending())
	}

	export := srv.auditRoute(apiRoute{Method: http.MethodGet, Pattern: "/v1/lifecycle/export"}, auditWrapped(auditFacetExport), next)
	rec = httptest.NewRecorder()
	err := export(rec, httptest.NewRequest(http.MethodGet, "/v1/lifecycle/export", nil))
	if err == nil || !errors.Is(err, err) || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("an export must fail closed with Retry-After while audit cannot be written, got err=%v retry-after=%q", err, rec.Header().Get("Retry-After"))
	}
	if served != 1 {
		t.Fatalf("the export must not have been served, served=%d", served)
	}
	if srv.deferredAudit.pending() != 1 {
		t.Fatalf("an export's audit is never deferred, pending=%d", srv.deferredAudit.pending())
	}

	// A failure that is not a read-only refusal still fails the read closed.
	srv.routeAudit = func(*http.Request, string, string, map[string]any) error {
		return errors.New("audit store unreachable")
	}
	if err := read(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/tests", nil)); err == nil {
		t.Fatal("an unrelated audit failure must still fail the read")
	}

	// Writes return: the deferred event is appended with its deferral stamped.
	var replayed []map[string]any
	srv.routeAuditReplay = func(_ context.Context, _, _, action, target string, data map[string]any) error {
		replayed = append(replayed, map[string]any{"action": action, "target": target, "deferred_at": data["deferred_at"], "reason": data["deferred_reason"], "facet": data["facet"]})
		return nil
	}
	if n := srv.FlushDeferredAudit(context.Background()); n != 1 {
		t.Fatalf("flushed %d, want 1", n)
	}
	if len(replayed) != 1 || replayed[0]["action"] != "access.read.tests" || replayed[0]["deferred_at"] == "" || replayed[0]["facet"] != "sensitive_read" {
		t.Fatalf("replayed event mismatch: %v", replayed)
	}
	if srv.deferredAudit.pending() != 0 {
		t.Fatal("queue must be empty after a successful flush")
	}

	// A replay that is refused again keeps the event at the head, in order.
	srv.routeAudit = func(*http.Request, string, string, map[string]any) error { return readOnlyRefusal() }
	for i := 0; i < 2; i++ {
		_ = read(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/tests", nil))
	}
	srv.routeAuditReplay = func(context.Context, string, string, string, string, map[string]any) error { return readOnlyRefusal() }
	if n := srv.FlushDeferredAudit(context.Background()); n != 0 || srv.deferredAudit.pending() != 2 {
		t.Fatalf("a refused replay must keep the queue intact: flushed=%d pending=%d", n, srv.deferredAudit.pending())
	}
}

// TestDeferredAuditQueueIsBounded: a failover that outlives the queue drops
// the oldest-unwritten events loudly (counted), never grows without bound.
func TestDeferredAuditQueueIsBounded(t *testing.T) {
	var q deferredAuditQueue
	for i := 0; i < deferredAuditMaxQueue; i++ {
		if !q.push(deferredAuditEvent{action: "a"}) {
			t.Fatalf("push %d refused below the bound", i)
		}
	}
	if q.push(deferredAuditEvent{action: "overflow"}) || q.dropped != 1 {
		t.Fatalf("the bound must refuse and count: dropped=%d", q.dropped)
	}
}
