// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/siem"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type blockingSIEMSender struct {
	mu      sync.Mutex
	got     [][]byte
	entered chan struct{}
	release chan struct{}
}

func (s *blockingSIEMSender) Send(ctx context.Context, payload []byte) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	select {
	case <-s.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	s.got = append(s.got, append([]byte(nil), payload...))
	s.mu.Unlock()
	return nil
}

func (s *blockingSIEMSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

// appendAudit writes one audit event to a tenant's chain (with a secret in the
// data, to assert redaction on export).
func appendAudit(t *testing.T, db *store.DB, tenant, action string) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, e := audit.TenantAppend(ctx, sc, "tester", action, "target-"+action,
			map[string]any{"outcome": "success", "password": "hunter2"})
		return e
	}); err != nil {
		t.Fatalf("append audit %q: %v", action, err)
	}
}

func tenantCursor(t *testing.T, db *store.DB, tenant string) int64 {
	t.Helper()
	var cursor int64
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		c, e := (store.SIEMDelivery{}).Cursor(ctx, sc)
		cursor = c
		return e
	}); err != nil {
		t.Fatalf("read cursor: %v", err)
	}
	return cursor
}

// The audit poller forwards exactly the calling tenant's events (tenant-scoped,
// no cross-tenant leak), redacts secrets, persists a cursor, and does not
// re-deliver on a second pass — the S32 done-when, against real Postgres + RLS.
func TestSIEMAuditDrainCursorAndScope(t *testing.T) {
	db := changeDB(t)
	tenantA := freshTenant(t, db, "siem-a")
	tenantB := freshTenant(t, db, "siem-b")
	appendAudit(t, db, tenantA, "alert.create")
	appendAudit(t, db, tenantA, "agent.delete")
	appendAudit(t, db, tenantB, "login") // must never appear in A's stream

	snk := &capSender{}
	fmtr, _ := siem.NewFormatter("ecs")
	fw := siem.NewForwarder(fmtr, snk, siem.Config{}, testLog())
	poller := NewSIEMAuditPoller(db.Pool(), fw, nil, true, time.Minute, testLog())

	if err := poller.drainTenant(context.Background(), tenantA); err != nil {
		t.Fatalf("drain A: %v", err)
	}
	// AUD-16: tenant A's two events are delivered as ONE batched POST (NDJSON),
	// not one request per event.
	recs := snk.records()
	if len(recs) != 1 {
		t.Fatalf("want 1 batched POST for tenant A, got %d", len(recs))
	}
	events := ecsBatchDocs(t, recs[0])
	if len(events) != 2 {
		t.Fatalf("want 2 events in the batch for tenant A, got %d", len(events))
	}
	for _, doc := range events {
		if org := doc["organization"].(map[string]any); org["id"] != tenantA {
			t.Fatalf("cross-tenant leak: organization.id=%v want %s", org["id"], tenantA)
		}
		if labels, ok := doc["labels"].(map[string]any); ok {
			if labels["password"] != "[redacted]" {
				t.Fatalf("secret not redacted on export: %v", labels["password"])
			}
		}
	}
	if d := fw.Stats().Delivered; d != 2 {
		t.Fatalf("forwarder delivered %d events, want 2", d)
	}

	cursor := tenantCursor(t, db, tenantA)
	if cursor <= 0 {
		t.Fatalf("cursor not persisted: %d", cursor)
	}

	// Second pass delivers nothing new (cursor durably advanced — no duplicates).
	if err := poller.drainTenant(context.Background(), tenantA); err != nil {
		t.Fatalf("re-drain A: %v", err)
	}
	if got := len(snk.records()); got != 1 {
		t.Fatalf("re-drain re-sent a batch: now %d POSTs", got)
	}
	if d := fw.Stats().Delivered; d != 2 {
		t.Fatalf("re-drain duplicated events: delivered now %d", d)
	}
	if again := tenantCursor(t, db, tenantA); again != cursor {
		t.Fatalf("cursor moved with no new events: %d -> %d", cursor, again)
	}
}

// ecsBatchDocs splits a batched NDJSON SIEM POST into its per-event ECS
// documents (AUD-16: one POST carries a whole page).
func ecsBatchDocs(t *testing.T, payload []byte) []map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	out := make([]map[string]any, 0, len(lines))
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(ln), &doc); err != nil {
			t.Fatalf("ecs batch line not json: %v (%q)", err, ln)
		}
		out = append(out, doc)
	}
	return out
}

// Two replicas may overlap briefly during failover even though the singleton
// lease is the outer guard. AUD-16 releases the DB transaction during the SIEM
// POST, so the storage-layer backstop is now the per-tenant export CLAIM (a
// short lease on siem_delivery): while poller A holds the claim and is
// delivering, poller B's claim attempt fails and it forwards nothing — so the
// page is delivered exactly once, with no transaction pinned across the POST.
func TestSIEMAuditConcurrentPollersDoNotDuplicateForward(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "siem-concurrent")
	appendAudit(t, db, tenant, "alert.create")
	appendAudit(t, db, tenant, "agent.delete")

	sender := &blockingSIEMSender{entered: make(chan struct{}, 4), release: make(chan struct{})}
	fmtr, _ := siem.NewFormatter("ecs")
	fw := siem.NewForwarder(fmtr, sender, siem.Config{}, testLog())
	pollerA := NewSIEMAuditPoller(db.Pool(), fw, nil, true, time.Minute, testLog())
	pollerB := NewSIEMAuditPoller(db.Pool(), fw, nil, true, time.Minute, testLog())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, poller := range []*SIEMAuditPoller{pollerA, pollerB} {
		go func(p *SIEMAuditPoller) {
			<-start
			errs <- p.drainTenant(ctx, tenant)
		}(poller)
	}
	close(start)

	select {
	case <-sender.entered: // the claim holder reached the external delivery
	case <-time.After(5 * time.Second):
		t.Fatal("first poller never reached SIEM sender")
	}
	// Keep the first delivery blocked long enough for the second poller to race.
	// Without the export claim, the loser would POST the same page here.
	select {
	case <-sender.entered:
		// A second entry before release is the old duplicate-forward race. Let
		// both finish so the final count below gives the actionable failure.
	case <-time.After(200 * time.Millisecond):
	}
	close(sender.release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent drain: %v", err)
		}
	}

	// Exactly one batch POST carrying exactly the 2 unique events — no duplicate
	// forward from the overlapping replica.
	if got := sender.count(); got != 1 {
		t.Fatalf("concurrent pollers sent %d batches, want exactly 1 (claim serializes delivery)", got)
	}
	if d := fw.Stats().Delivered; d != 2 {
		t.Fatalf("concurrent pollers delivered %d events, want exactly the 2 unique audit events", d)
	}
	if cursor := tenantCursor(t, db, tenant); cursor != 2 {
		t.Fatalf("cursor did not advance to 2 after delivery: %d", cursor)
	}
}

// A flaky SIEM (the sink fails its first calls) must not drop audit events: the
// forwarder retries inside Deliver, so every event still arrives exactly once.
func TestSIEMAuditRetryNoDrop(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "siem-retry")
	for i := 0; i < 4; i++ {
		appendAudit(t, db, tenant, fmt.Sprintf("act.%d", i))
	}

	snk := &capSender{failFirst: 3} // first three batch POSTs fail
	fmtr, _ := siem.NewFormatter("cef")
	fw := siem.NewForwarder(fmtr, snk,
		siem.Config{RetryBackoff: 2 * time.Millisecond, MaxBackoff: 2 * time.Millisecond}, testLog())
	poller := NewSIEMAuditPoller(db.Pool(), fw, nil, true, time.Minute, testLog())

	if err := poller.drainTenant(context.Background(), tenant); err != nil {
		t.Fatalf("drain: %v", err)
	}
	// AUD-16: the 4 events ride one batched POST, retried as a whole until it
	// lands — so one payload arrives, carrying all 4 CEF records, and nothing
	// is dropped.
	recs := snk.records()
	if len(recs) != 1 {
		t.Fatalf("retry forwarded %d batches, want 1 (whole batch retried)", len(recs))
	}
	if lines := strings.Split(strings.TrimSpace(string(recs[0])), "\n"); len(lines) != 4 {
		t.Fatalf("batch carried %d CEF records, want 4", len(lines))
	}
	if st := fw.Stats(); st.Delivered != 4 {
		t.Fatalf("retry dropped events: delivered %d want 4 (%+v)", st.Delivered, st)
	}
	if st := fw.Stats(); st.Retried < 3 {
		t.Fatalf("expected at least 3 retries, got %+v", st)
	}
	if c := tenantCursor(t, db, tenant); c <= 0 {
		t.Fatalf("cursor not advanced after retried delivery: %d", c)
	}
}
