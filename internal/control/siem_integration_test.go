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
	poller := NewSIEMAuditPoller(db.Pool(), fw, nil, time.Minute, testLog())

	if err := poller.drainTenant(context.Background(), tenantA); err != nil {
		t.Fatalf("drain A: %v", err)
	}
	recs := snk.records()
	if len(recs) != 2 {
		t.Fatalf("want 2 records for tenant A, got %d", len(recs))
	}
	for _, r := range recs {
		var doc map[string]any
		if err := json.Unmarshal(r, &doc); err != nil {
			t.Fatalf("ecs json: %v", err)
		}
		if org := doc["organization"].(map[string]any); org["id"] != tenantA {
			t.Fatalf("cross-tenant leak: organization.id=%v want %s", org["id"], tenantA)
		}
		if labels, ok := doc["labels"].(map[string]any); ok {
			if labels["password"] != "[redacted]" {
				t.Fatalf("secret not redacted on export: %v", labels["password"])
			}
		}
	}

	cursor := tenantCursor(t, db, tenantA)
	if cursor <= 0 {
		t.Fatalf("cursor not persisted: %d", cursor)
	}

	// Second pass delivers nothing new (cursor durably advanced — no duplicates).
	if err := poller.drainTenant(context.Background(), tenantA); err != nil {
		t.Fatalf("re-drain A: %v", err)
	}
	if got := len(snk.records()); got != 2 {
		t.Fatalf("re-drain duplicated events: now %d records", got)
	}
	if again := tenantCursor(t, db, tenantA); again != cursor {
		t.Fatalf("cursor moved with no new events: %d -> %d", cursor, again)
	}
}

// Two replicas may overlap briefly during failover even though the singleton
// lease is the outer guard. The cursor row lock is the storage-layer backstop:
// while poller A is delivering, poller B cannot read the same cursor/page.
func TestSIEMAuditConcurrentPollersDoNotDuplicateForward(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "siem-concurrent")
	appendAudit(t, db, tenant, "alert.create")
	appendAudit(t, db, tenant, "agent.delete")

	sender := &blockingSIEMSender{entered: make(chan struct{}, 4), release: make(chan struct{})}
	fmtr, _ := siem.NewFormatter("ecs")
	fw := siem.NewForwarder(fmtr, sender, siem.Config{}, testLog())
	pollerA := NewSIEMAuditPoller(db.Pool(), fw, nil, time.Minute, testLog())
	pollerB := NewSIEMAuditPoller(db.Pool(), fw, nil, time.Minute, testLog())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	case <-sender.entered: // first poller reached the external delivery
	case <-time.After(5 * time.Second):
		t.Fatal("first poller never reached SIEM sender")
	}
	// Keep the first delivery blocked long enough for the second poller to race.
	// Without the cursor row lock, both enter the sender with the same first event.
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

	if got := sender.count(); got != 2 {
		t.Fatalf("concurrent pollers forwarded %d records, want exactly the 2 unique audit events", got)
	}
	if cursor := tenantCursor(t, db, tenant); cursor <= 0 {
		t.Fatalf("cursor did not advance after serialized delivery: %d", cursor)
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

	snk := &capSender{failFirst: 3} // first three deliveries fail
	fmtr, _ := siem.NewFormatter("cef")
	fw := siem.NewForwarder(fmtr, snk,
		siem.Config{RetryBackoff: 2 * time.Millisecond, MaxBackoff: 2 * time.Millisecond}, testLog())
	poller := NewSIEMAuditPoller(db.Pool(), fw, nil, time.Minute, testLog())

	if err := poller.drainTenant(context.Background(), tenant); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if got := len(snk.records()); got != 4 {
		t.Fatalf("retry dropped events: got %d want 4", got)
	}
	if st := fw.Stats(); st.Retried < 3 {
		t.Fatalf("expected at least 3 retries, got %+v", st)
	}
	if c := tenantCursor(t, db, tenant); c <= 0 {
		t.Fatalf("cursor not advanced after retried delivery: %d", c)
	}
}
