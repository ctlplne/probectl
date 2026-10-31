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
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestHistoryJournalPostgresTenantEraseRetriesKnownDrain(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	restore := activityAuditFault(t, f.admin, "audit_events", f.red.scope.TenantID)
	returned := false
	err := f.journal.WithReadLease(f.red.requestContext(t), f.red.authorizeHistory, func(context.Context) error {
		private := []byte("owned callback buffer")
		defer clear(private)
		returned = true
		return nil
	})
	if !errors.Is(err, ErrJournalUnavailable) || !returned || f.active(t, f.red.scope.TenantID) != 1 {
		t.Fatal("owned actual drain did not retain its failed audit acknowledgement", err)
	}
	restore()
	fenced := false
	operational := f.operational(t, f.red.scope.TenantID)
	result, err := NewJournal(f.pool).EraseTenant(operational, CancellationBudget{Rows: 1, TimeLimit: 3 * time.Second}, allowActivityMaintenance, func(ctx context.Context) error {
		if f.active(t, f.red.scope.TenantID) != 0 {
			t.Error("global fence entered before known actual drain was acknowledged")
		}
		fenced = true
		return tenancy.InProvider(ctx, f.pool, func(ctx context.Context, q tenancy.Querier) error {
			if err := tenancy.LockTenantWrites(ctx, q, f.red.scope.TenantID); err != nil {
				return err
			}
			if err := audit.LockTenantStream(ctx, q, f.red.scope.TenantID); err != nil {
				return err
			}
			if _, err := q.Exec(ctx, `UPDATE public.tenants SET status='offboarding',audit_write_fenced_at=clock_timestamp() WHERE id=$1::uuid`, f.red.scope.TenantID); err != nil {
				return err
			}
			_, err := audit.ProviderAppendTx(ctx, q, "owned-fixture", "owned.history_erase_fence", f.red.scope.TenantID, map[string]any{"tenant_id": f.red.scope.TenantID})
			return err
		})
	})
	if err != nil || !result.Installed || !fenced || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("full-tenant lifecycle failed to retry this process's known actual drain", err)
	}
	var pending bool
	if err := f.admin.QueryRow(t.Context(), `SELECT invalidating FROM flow_conversation_epochs WHERE tenant_id=$1::uuid`, f.red.scope.TenantID).Scan(&pending); err != nil || !pending {
		t.Fatal("storage-family purge cleared its epoch before canonical full teardown", err)
	}
}

func TestHistoryJournalPostgresExactFamilyLocksWithoutSourceSelect(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	if _, err := f.admin.Exec(t.Context(), `REVOKE SELECT ON flow_conversation_messages FROM probectl_app`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.admin.Exec(context.Background(), `GRANT SELECT ON flow_conversation_messages TO probectl_app`); err != nil {
			t.Error(err)
		}
	})
	held, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	finished := make(chan error, 1)
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		finished <- f.journal.scoped(f.operational(t, f.red.scope.TenantID), func(context.Context, tenancy.Scope) error {
			close(held)
			<-release
			return nil
		})
	}()
	t.Cleanup(func() {
		finish()
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Error("owned metadata transaction failed to drain")
		}
	})
	select {
	case <-held:
	case err := <-finished:
		t.Fatal("source-free private family locking requires SELECT", err)
	case <-time.After(5 * time.Second):
		t.Fatal("owned family lock acquisition timed out")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ddl, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ddl.Rollback(context.Background()) }()
	var pid int
	if err := ddl.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	ddlCtx, cancelDDL := context.WithCancel(ctx)
	defer cancelDDL()
	altered := make(chan error, 1)
	go func() {
		_, err := ddl.Exec(ddlCtx, `ALTER TABLE public.flow_conversation_messages ADD COLUMN probectl_qa_beta_lock_probe integer`)
		altered <- err
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := f.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='public.flow_conversation_messages'::regclass AND mode='AccessExclusiveLock' AND NOT granted)`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-altered:
			t.Fatal("owned DDL crossed an active exact-family transaction", err)
		case <-ctx.Done():
			t.Fatal("owned DDL waiter never observed", ctx.Err())
		case <-ticker.C:
		}
	}
	cancelDDL()
	if err := <-altered; err == nil {
		t.Fatal("owned waiting DDL committed without the family transaction ending")
	}
	if err := ddl.Rollback(context.Background()); err != nil {
		// pgx may already close/roll back the connection on cancellation.
		if ctx.Err() != nil {
			t.Fatal("owned DDL cancellation exceeded its bound", err)
		}
	}
	finish()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal("source-free locked operation failed after owned DDL cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned locked operation failed to return")
	}
}
