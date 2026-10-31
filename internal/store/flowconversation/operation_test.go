// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestHistoryOperationRefusesInvalidAuthorityBeforeSQL(t *testing.T) {
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	var journal *Journal
	called := false
	fn := func(context.Context) error { called = true; return nil }
	for _, bad := range []context.Context{f.context, tenancy.WithTenant(ctx, tenancy.ID(f.credentialID)), auth.WithPrincipal(ctx, &auth.Principal{TenantID: f.scope.TenantID, UserID: f.scope.OwnerID})} {
		if err := journal.WithReadLease(bad, f.authorizeHistory, fn); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("invalid current identity reached lease storage", err)
		}
	}
	if err := journal.WithReadLease(ctx, nil, fn); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing authority reached SQL", err)
	}
	if err := journal.WithReadLease(ctx, f.authorizeHistory, nil); !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("nil operation reached SQL", err)
	}
	if err := journal.WithReadLease(ctx, f.authorizeHistory, fn); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("healthy current identity missed unavailable port", err)
	}
	authorize := func(context.Context, string) error { called = true; return nil }
	for _, bad := range []context.Context{t.Context(), ctx, tenancy.WithTenant(t.Context(), tenancy.ID("invalid"))} {
		if err := journal.WithMaintenanceLease(bad, authorize, fn); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("request or unscoped context reached operational lease", err)
		}
	}
	if called {
		t.Fatal("invalid context invoked operational authority or callback")
	}
	operational := tenancy.WithTenant(t.Context(), tenancy.ID(f.scope.TenantID))
	if err := journal.WithMaintenanceLease(operational, nil, fn); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing independent maintenance authority reached SQL", err)
	}
	if err := journal.WithMaintenanceLease(operational, func(context.Context, string) error { return nil }, fn); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("healthy maintenance identity missed unavailable port", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := journal.WithReadLease(canceled, f.authorizeHistory, fn); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled read reached lease", err)
	}
	if called {
		t.Fatal("refused operation executed callback")
	}
}

func TestHistoryOperationNestedIdentityAndExpiredContext(t *testing.T) {
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	id, err := historyIdentityFor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	journal := NewJournal(nil)
	lease := &operationLease{journal: journal, owner: id, generation: 1}
	owned, cancel := context.WithCancel(ctx)
	nested := context.WithValue(owned, operationLeaseKey{}, lease)
	calls := 0
	fn := func(context.Context) error { calls++; return nil }
	if err := journal.WithReadLease(nested, f.authorizeHistory, fn); !errors.Is(err, ErrJournalUnavailable) || calls != 0 {
		t.Fatal("synthetic nested context bypassed current SQL epoch", err)
	}
	if err := NewJournal(nil).WithReadLease(nested, f.authorizeHistory, fn); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("nested operation crossed Journal", err)
	}
	changed := id
	changed.owner = f.credentialID
	foreign := context.WithValue(ctx, operationLeaseKey{}, &operationLease{journal: journal, owner: changed})
	if err := journal.WithReadLease(foreign, f.authorizeHistory, fn); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("nested operation crossed owner", err)
	}
	changed = id
	changed.origin = auth.WorkerCredentialRef{}
	foreign = context.WithValue(ctx, operationLeaseKey{}, &operationLease{journal: journal, owner: changed})
	if err := journal.WithReadLease(foreign, f.authorizeHistory, fn); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("nested operation crossed credential", err)
	}
	lease.finish(cancel)
	// WithoutCancel retains context values. The opaque value must also expire.
	if err := journal.WithReadLease(context.WithoutCancel(nested), f.authorizeHistory, fn); !errors.Is(err, ErrMessageDenied) || calls != 0 {
		t.Fatal("escaped context revived released lease", err)
	}
}

func TestHistoryOperationFinishWaitsForActualNestedDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease := &operationLease{}
		if !lease.enter() {
			t.Fatal("new lease refused nested work")
		}
		ctx, cancel := context.WithCancel(t.Context())
		release, finished := make(chan struct{}), make(chan struct{})
		var drained atomic.Bool
		go func() { <-ctx.Done(); <-release; drained.Store(true); lease.readers.Done() }()
		go func() { lease.finish(cancel); close(finished) }()
		synctest.Wait()
		select {
		case <-finished:
			t.Fatal("cancellation stood in for actual nested drain")
		default:
		}
		if lease.enter() {
			lease.readers.Done()
			t.Fatal("closing lease admitted more work")
		}
		close(release)
		synctest.Wait()
		select {
		case <-finished:
			if !drained.Load() {
				t.Fatal("finish preceded actual callback return")
			}
		default:
			t.Fatal("drained lease did not finish")
		}
	})
}
