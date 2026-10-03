//go:build integration

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// RTO-20: the persisted notification bookkeeping (firing-since + last-notified)
// is tenant-confined by forced RLS, upserts idempotently on re-notify, lists
// for a leadership reload, and deletes on resolve. One tenant never sees
// another's notification state (G7-1).
func TestAlertNotificationsStoreIsolationAndLifecycle(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "alertnotif-a-"+suffix, "alertnotif-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "alertnotif-b-"+suffix, "alertnotif-b")
	if err != nil {
		t.Fatal(err)
	}

	fp := "r1|target=db;"
	since := time.Now().UTC().Truncate(time.Millisecond)
	first := since.Add(15 * time.Second)

	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (AlertNotifications{}).Upsert(ctx, sc, AlertNotification{Fingerprint: fp, FiringSince: since, LastNotified: first}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		// Re-notify: the ON CONFLICT path advances last-notified, firing-since holds.
		renotified := first.Add(5 * time.Minute)
		if err := (AlertNotifications{}).Upsert(ctx, sc, AlertNotification{Fingerprint: fp, FiringSince: since, LastNotified: renotified}); err != nil {
			t.Fatalf("re-upsert: %v", err)
		}
		got, err := (AlertNotifications{}).List(ctx, sc)
		if err != nil || len(got) != 1 {
			t.Fatalf("list: %v / %d", err, len(got))
		}
		if !got[0].FiringSince.Equal(since) || !got[0].LastNotified.Equal(renotified) || got[0].Fingerprint != fp {
			t.Fatalf("persisted notification state = %+v (want since=%v last=%v)", got[0], since, renotified)
		}
		return nil
	})

	// Tenant B is isolated: it sees none of tenant A's notification state.
	inTenant(ctx, t, pool, b.ID, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := (AlertNotifications{}).List(ctx, sc)
		if err != nil || len(got) != 0 {
			t.Fatalf("tenant B sees tenant A's notification state: %+v err=%v", got, err)
		}
		return nil
	})

	// Resolve: the row is deleted so a future episode starts clean.
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (AlertNotifications{}).Delete(ctx, sc, fp); err != nil {
			t.Fatalf("delete: %v", err)
		}
		got, err := (AlertNotifications{}).List(ctx, sc)
		if err != nil || len(got) != 0 {
			t.Fatalf("delete left rows: %+v err=%v", got, err)
		}
		return nil
	})
}
