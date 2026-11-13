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

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/crypto"
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
		if err := (AlertNotifications{}).Upsert(ctx, sc, AlertNotification{Fingerprint: fp, FiringSince: since}); err != nil {
			t.Fatalf("persist held firing: %v", err)
		}
		held, err := (AlertNotifications{}).List(ctx, sc)
		if err != nil || len(held) != 1 || !held[0].LastNotified.IsZero() || !held[0].FiringSince.Equal(since) {
			t.Fatalf("held episode lost its original clock or became a delivered notification: %+v err=%v", held, err)
		}
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
		population, err := (AlertNotifications{}).GetPopulation(ctx, sc, []string{fp, "absent"}, 1<<20)
		if err != nil || len(population) != 1 || population[fp] == nil ||
			!population[fp].FiringSince.Equal(since) || !population[fp].LastNotified.Equal(renotified) {
			t.Fatal("complete episode read changed original clocks or invented absent keys", population, err)
		}
		foreign := tenancy.WithTenant(ctx, tenancy.ID(b.ID))
		if _, err := (AlertNotifications{}).GetPopulation(foreign, sc, []string{fp}, 1<<20); err != alert.ErrDependencyEvidence {
			t.Fatal("episode batch accepted a mismatched tenant scope", err)
		}
		if _, err := (AlertNotifications{}).GetPopulation(ctx, sc, []string{fp, fp}, 1<<20); err != alert.ErrDependencyEvidence {
			t.Fatal("episode batch accepted duplicate decision keys", err)
		}
		if _, err := (AlertNotifications{}).GetPopulation(ctx, sc, []string{fp}, 4095); err != ErrAlertDependencyBudget {
			t.Fatal("episode batch escaped finite admission", err)
		}
		return nil
	})

	// Tenant B is isolated: it sees none of tenant A's notification state.
	inTenant(ctx, t, pool, b.ID, func(ctx context.Context, sc tenancy.Scope) error {
		population, err := (AlertNotifications{}).GetPopulation(ctx, sc, []string{fp, "absent"}, 1<<20)
		if err != nil || len(population) != 0 {
			t.Fatal("episode batch exposed the sibling tenant", population, err)
		}
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

func TestAlertDependencyNotificationStateKeepsSharedEpisodeKeysAndClears(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	var tenants []string
	for _, lane := range []string{"a", "b"} {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("dep-state-%s-%d", lane, time.Now().UnixNano()), "Dependency state")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	transition, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "same-rule|same-series"
	since := time.Now().UTC().Truncate(time.Microsecond)
	for i, tenant := range tenants {
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			held := i == 0
			n := AlertNotification{Fingerprint: fingerprint, FiringSince: since, LastNotified: since.Add(time.Second), Dependency: &alert.DependencyNotificationState{Held: held, TransitionID: transition}}
			if err := (AlertNotifications{}).Upsert(ctx, sc, n); err != nil {
				return err
			}
			got, err := (AlertNotifications{}).Get(ctx, sc, fingerprint)
			if err != nil || got == nil || got.Dependency == nil || got.Dependency.Held != held || got.Dependency.TransitionID != transition {
				t.Fatal("shared keys or transition crossed tenant state", got, err)
			}
			var visible int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM alert_notifications WHERE fingerprint=$1`, fingerprint).Scan(&visible); err != nil {
				return err
			}
			if visible != 1 {
				t.Fatal("storage RLS did not confine shared notification keys", visible)
			}
			other := tenants[1-i]
			if got, err := (AlertNotifications{}).Get(tenancy.WithTenant(ctx, tenancy.ID(other)), sc, fingerprint); err == nil || got != nil {
				t.Fatal("foreign context borrowed a notification scope", got, err)
			}
			// An ordinary timestamp update in the same episode preserves the
			// source publisher's marker; an explicit ordinary-delivery decision
			// clears held but retains a known transition even with a zero clock.
			n.Dependency = nil
			if err := (AlertNotifications{}).Upsert(ctx, sc, n); err != nil {
				return err
			}
			got, err = (AlertNotifications{}).Get(ctx, sc, fingerprint)
			if err != nil || got.Dependency == nil || got.Dependency.Held != held {
				t.Fatal("ordinary timestamp update erased dependency bookkeeping", got, err)
			}
			n.LastNotified = time.Time{}
			n.Dependency = &alert.DependencyNotificationState{}
			if err := (AlertNotifications{}).Upsert(ctx, sc, n); err != nil {
				return err
			}
			got, err = (AlertNotifications{}).Get(ctx, sc, fingerprint)
			if err != nil || got.Dependency == nil || got.Dependency.Held || got.Dependency.TransitionID != transition || !got.LastNotified.IsZero() {
				t.Fatal("explicit clear became an ambiguous legacy held marker", got, err)
			}
			for _, bad := range []alert.DependencyNotificationState{{Held: true}, {Held: true, TransitionID: "00000000-0000-0000-0000-000000000000"}, {TransitionID: "untrusted"}} {
				n.Dependency = &bad
				if err := (AlertNotifications{}).Upsert(ctx, sc, n); err == nil {
					t.Fatal("invalid transition acquired durable state", bad)
				}
			}
			n.Dependency = nil
			n.FiringSince = since.Add(time.Minute)
			if err := (AlertNotifications{}).Upsert(ctx, sc, n); err != nil {
				return err
			}
			got, err = (AlertNotifications{}).Get(ctx, sc, fingerprint)
			if err != nil || got.Dependency != nil {
				t.Fatal("old transition leaked into the next episode", got, err)
			}
			return nil
		})
	}
}
