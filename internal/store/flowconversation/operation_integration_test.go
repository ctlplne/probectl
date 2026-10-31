// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowconversation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestHistoryJournalPostgresOperationDrainAndTenantIsolation(t *testing.T) {
	admin, base := journalFixture(t)
	if admin == nil {
		return
	}
	// Three simultaneous leases plus their working transactions fit this owned
	// pool. The separate four-connection tests retain the minimum-capacity case.
	config := base.Config().Copy()
	config.MaxConns = 12
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	journal := NewJournal(pool)
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	blue, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{f.scope.TenantID, blue} {
		if _, err := admin.Exec(ctx, `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned drain fixture')`, tenant, "probectl-qa-beta-drain-"+strings.ReplaceAll(tenant, "-", "")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{f.scope.TenantID, blue}); err != nil {
			t.Error("owned drain tenant cleanup failed", err)
		}
	})
	applicationError := errors.New("application policy refused operation")
	if err := journal.WithReadLease(ctx, f.authorizeHistory, func(context.Context) error { return applicationError }); !errors.Is(err, applicationError) {
		t.Fatal("read lease relabeled application policy as storage failure", err)
	}
	operational := func(tenant string) context.Context { return tenancy.WithTenant(t.Context(), tenancy.ID(tenant)) }
	authorize := func(ctx context.Context, tenant string) error {
		current, ok := tenancy.FromContext(ctx)
		if !ok || current.String() != tenant {
			return ErrMessageDenied
		}
		return ctx.Err()
	}
	started, canceled, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	readCtx, cancelRead := context.WithCancel(ctx)
	var releaseOnce sync.Once
	releaseRead := func() { releaseOnce.Do(func() { close(release) }) }
	var escaped context.Context
	readError := make(chan error, 1)
	go func() {
		defer close(ended)
		readError <- journal.WithReadLease(readCtx, f.authorizeHistory, func(current context.Context) error {
			escaped = current
			// A nested metadata operation uses working capacity, not another lease.
			if err := journal.WithReadLease(current, f.authorizeHistory, func(nested context.Context) error { _, err := journal.CandidateEpoch(nested); return err }); err != nil {
				return err
			}
			close(started)
			<-current.Done()
			close(canceled)
			<-release // Deliberately late IO: cancellation alone is not a drain.
			return current.Err()
		})
	}()
	t.Cleanup(func() {
		cancelRead()
		releaseRead()
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Error("owned read callback failed cleanup")
		}
	})
	select {
	case <-started:
	case err := <-readError:
		t.Fatal("read lease failed before callback", err)
	case <-time.After(5 * time.Second):
		t.Fatal("read callback did not start")
	}
	cancelRead()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("read callback did not receive cancellation")
	}
	var maintenanceEntered atomic.Bool
	waiting, stop := context.WithTimeout(operational(f.scope.TenantID), 750*time.Millisecond)
	defer stop()
	maintenanceError := make(chan error, 1)
	go func() {
		maintenanceError <- journal.WithMaintenanceLease(waiting, authorize, func(context.Context) error { maintenanceEntered.Store(true); return nil })
	}()
	// Positively observe a PostgreSQL advisory waiter, rather than infer a
	// barrier from a goroutine that may never have attempted storage.
	observed := false
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for !observed {
		if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE '%probectl.flow_conversations.operation:%')`).Scan(&observed); err != nil {
			t.Fatal(err)
		}
		if observed {
			break
		}
		select {
		case err := <-maintenanceError:
			t.Fatal("maintenance did not wait behind undrained IO", err)
		case <-ticker.C:
		}
	}
	blueCtx, stopBlue := context.WithTimeout(operational(blue), 300*time.Millisecond)
	defer stopBlue()
	blueEntered := false
	if err := journal.WithMaintenanceLease(blueCtx, authorize, func(context.Context) error { blueEntered = true; return nil }); err != nil || !blueEntered {
		t.Fatal("red operation blocked independent blue tenant", err)
	}
	if err := <-maintenanceError; !errors.Is(err, context.DeadlineExceeded) || maintenanceEntered.Load() {
		t.Fatal("cancellation admitted maintenance before actual drain", err)
	}
	releaseRead()
	select {
	case err := <-readError:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("canceled operation returned success", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("released callback did not drain")
	}
	if err := journal.WithReadLease(context.WithoutCancel(escaped), f.authorizeHistory, func(context.Context) error { t.Error("escaped context reentered callback"); return nil }); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("released SQL lease revived", err)
	}
	entered := false
	if err := journal.WithMaintenanceLease(operational(f.scope.TenantID), authorize, func(context.Context) error { entered = true; return nil }); err != nil || !entered {
		t.Fatal("drained read retained tenant barrier", err)
	}
	if err := journal.WithReadLease(ctx, f.authorizeHistory, func(context.Context) error { return nil }); err != nil {
		t.Fatal("drain leaked pool admission", err)
	}
}
