// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowconversation

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func seedSubjectOperation(t *testing.T, journal *Journal, f messageCodecFixture, expires time.Time) {
	t.Helper()
	meta := inputMetadata()
	if !expires.IsZero() {
		meta.ExpiresAt = expires
	}
	input, err := f.codec.PrepareInput(f.requestContext(t), f.scope, meta, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"question":"subject@example.test"}`), f.authorize)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.AdmitInput(f.requestContext(t), input, f.authorize); err != nil {
		t.Fatal(err)
	}
}

// A small actual encrypted source for admission/drain tests. This fixed fixture
// read deliberately has no retention filter; it is not the production bounded
// semantic matcher, descendant closure or native document validation service.
func visitSubjectOperationFixture(ctx context.Context, journal *Journal, f messageCodecFixture, visit func(context.Context, []byte) error) error {
	return journal.withSubjectReader(ctx, func(ctx context.Context) error {
		var header, payload string
		if err := journal.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT private_header,private_payload FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid AND message_id=$4::uuid AND revision=$5`, f.scope.TenantID, f.scope.OwnerID, f.scope.ConversationID, f.scope.MessageID, int64(f.scope.Revision)).Scan(&header, &payload)
		}); err != nil {
			return err
		}
		body, err := f.codec.Open(ctx, f.scope, SealedMessage{&sealedMessageParts{header: header, payload: payload}}, func(ctx context.Context, scope MessageScope, _ auth.WorkerCredentialRef, _ []string) error {
			if scope != f.scope {
				return ErrMessageDenied
			}
			lease, _ := ctx.Value(subjectSourceLeaseKey{}).(*subjectSourceLease)
			return journal.checkSubjectSource(ctx, lease)
		})
		if err != nil {
			return err
		}
		defer clear(body)
		return visit(ctx, body)
	})
}

func subjectOperationIntent(t *testing.T, f activityFixture) Invalidation {
	t.Helper()
	operational := f.operational(t, f.red.scope.TenantID)
	plan, err := f.red.codec.PrepareSubjectErasurePlan(operational, mustInvalidationUUID(t), "subject@example.test", []string{f.red.scope.OwnerID})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.journal.BeginSubjectInvalidation(operational, f.red.codec, plan, allowActivityMaintenance)
	if err != nil {
		t.Fatal(err)
	}
	return pending
}

func TestHistoryJournalPostgresSubjectPendingSourcePurposeAndExpiredBody(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	expires := time.Now().Add(time.Second)
	seedSubjectOperation(t, f.journal, f.red, expires)
	seedSubjectOperation(t, f.journal, f.blue, time.Time{})
	select {
	case <-time.After(time.Until(expires) + 10*time.Millisecond):
	case <-t.Context().Done():
		t.Fatal("fixture expiry wait canceled")
	}
	pending := subjectOperationIntent(t, f)
	operational := f.operational(t, f.red.scope.TenantID)
	var borrowed []byte
	var frozen SubjectErasurePlan
	err := f.journal.withSubjectMatchSource(operational, f.red.codec, pending, allowActivityMaintenance, func(current context.Context, plan SubjectErasurePlan) error {
		frozen = plan
		if f.active(t, f.red.scope.TenantID) != 1 || plan.value == nil || plan.value.wire.Subject != "subject@example.test" {
			t.Error("source entered before durable registration and exact plan")
		}
		if _, err := maintenanceTenant(current); !errors.Is(err, ErrMessageDenied) {
			t.Error("matching context became general maintenance authority", err)
		}
		foreign := tenancy.WithTenant(current, tenancy.ID(f.blue.scope.TenantID))
		if err := f.journal.withSubjectReader(foreign, func(context.Context) error { t.Error("foreign source entered"); return nil }); !errors.Is(err, ErrMessageDenied) {
			t.Error("matching context changed tenant", err)
		}
		mixed := auth.WithPrincipal(current, auth.PrincipalFrom(f.red.requestContext(t)))
		if err := f.journal.withSubjectReader(mixed, func(context.Context) error { t.Error("creator source entered"); return nil }); !errors.Is(err, ErrMessageDenied) {
			t.Error("matching context borrowed a creator Principal", err)
		}
		return visitSubjectOperationFixture(current, f.journal, f.red, func(_ context.Context, body []byte) error {
			borrowed = body
			if !bytes.Contains(body, []byte("subject@example.test")) {
				t.Error("expired encrypted fixture was not actually opened")
			}
			return nil
		})
	})
	if err != nil || len(borrowed) == 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) || f.active(t, f.red.scope.TenantID) != 0 || frozen.value == nil || frozen.value.wire.Subject != "" {
		t.Fatal("purpose-bound source did not clear actual buffers and retire", err)
	}
	if _, err := f.journal.CandidateEpoch(f.red.requestContext(t)); !errors.Is(err, ErrJournalGeneration) {
		t.Fatal("matching cleared the durable refusal marker", err)
	}
	if _, err := f.journal.Lookup(f.blue.requestContext(t), f.blue.scope.ConversationID, Revision{MessageID: f.blue.scope.MessageID, Revision: f.blue.scope.Revision}, 1<<20, f.blue.authorizeHistory); err != nil {
		t.Fatal("red purpose-bound source changed healthy blue history", err)
	}
	var allowed atomic.Bool
	allowed.Store(true)
	current := func(ctx context.Context, tenant string) error {
		if !allowed.Load() {
			return ErrMessageDenied
		}
		return allowActivityMaintenance(ctx, tenant)
	}
	err = f.journal.withSubjectMatchSource(operational, f.red.codec, pending, current, func(ctx context.Context, _ SubjectErasurePlan) error {
		allowed.Store(false)
		_ = f.journal.withSubjectReader(ctx, func(context.Context) error { t.Error("revoked reader opened source"); return nil })
		allowed.Store(true)
		return nil // deliberately ignore the nested failure
	})
	if !errors.Is(err, ErrMessageDenied) || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("ignored matching-reader failure became clean success", err)
	}
	original := f.journal.record
	f.journal.record = func(context.Context, tenancy.Scope, string, string, string, map[string]any) error {
		return errors.New("owned subject start audit failure")
	}
	entered := false
	err = f.journal.withSubjectMatchSource(operational, f.red.codec, pending, current, func(context.Context, SubjectErasurePlan) error { entered = true; return nil })
	f.journal.record = original
	if entered || !errors.Is(err, ErrJournalUnavailable) || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("failed source audit admitted or retained work", err)
	}
}

func TestHistoryJournalPostgresSubjectPendingSourceLeaseLossRequiresActualDrain(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedSubjectOperation(t, f.journal, f.red, time.Time{})
	seedSubjectOperation(t, f.journal, f.blue, time.Time{})
	pending := subjectOperationIntent(t, f)
	operational := f.operational(t, f.red.scope.TenantID)
	opened, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	outerReturned := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	var allowed atomic.Bool
	allowed.Store(true)
	authorize := func(ctx context.Context, tenant string) error {
		if !allowed.Load() {
			return ErrMessageDenied
		}
		return allowActivityMaintenance(ctx, tenant)
	}
	finished := make(chan error, 1)
	childDone := make(chan error, 1)
	ended := make(chan struct{})
	var borrowed []byte
	var frozen SubjectErasurePlan
	var sourceContext context.Context
	go func() {
		defer close(ended)
		finished <- f.journal.withSubjectMatchSource(operational, f.red.codec, pending, authorize, func(ctx context.Context, plan SubjectErasurePlan) error {
			defer close(outerReturned)
			sourceContext = ctx
			frozen = plan
			go func() {
				childDone <- visitSubjectOperationFixture(ctx, f.journal, f.red, func(ctx context.Context, body []byte) error {
					borrowed = body
					close(opened)
					<-ctx.Done()
					close(canceled)
					<-release // actual buffer remains live despite cancellation
					return ctx.Err()
				})
			}()
			<-opened
			<-ctx.Done() // only the live authority watcher can cancel this phase
			return nil   // outer callback returns before its nested source reader
		})
	}()
	t.Cleanup(func() {
		allowed.Store(false)
		unblock()
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Error("owned subject matcher did not actually drain")
		}
	})
	select {
	case <-opened:
	case err := <-finished:
		t.Fatal("actual pending source did not open", err)
	case <-time.After(5 * time.Second):
		t.Fatal("subject source admission timed out")
	}
	allowed.Store(false)
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("live privacy authority revocation did not cancel matching")
	}
	select {
	case <-outerReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("revocation did not return the outer matching callback")
	}
	if !errors.Is(context.Cause(sourceContext), ErrMessageDenied) {
		t.Fatal("matching cancellation was not caused by current authority loss", context.Cause(sourceContext))
	}
	if f.active(t, f.red.scope.TenantID) != 1 || frozen.value == nil || frozen.value.wire.Subject == "" {
		t.Fatal("revocation acknowledged a still-live matching buffer")
	}
	select {
	case err := <-finished:
		t.Fatal("outer callback return acknowledged a held nested source", err)
	default:
	}
	var pid int
	if err := f.admin.QueryRow(t.Context(), `WITH lease_key AS(SELECT hashtextextended('probectl.flow_conversations.operation:'||$1::text,0) AS value)
 SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid,lease_key WHERE l.locktype='advisory' AND l.granted AND l.mode='ExclusiveLock' AND l.objsubid=1 AND l.classid=((lease_key.value>>32)&4294967295)::oid AND l.objid=(lease_key.value&4294967295)::oid AND a.datname=current_database() AND a.query LIKE '%probectl.flow_conversations.operation:%'`, f.red.scope.TenantID).Scan(&pid); err != nil {
		t.Fatal("owned exact pending family lease was not observed", err)
	}
	var killed bool
	if err := f.admin.QueryRow(t.Context(), `SELECT pg_terminate_backend($1)`, pid).Scan(&killed); err != nil || !killed {
		t.Fatal("owned exact family-lease fault failed", err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), f.pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	replica := NewJournal(pool)
	entered := false
	if err := replica.withSubjectMatchSource(operational, f.red.codec, pending, allowActivityMaintenance, func(context.Context, SubjectErasurePlan) error { entered = true; return nil }); !errors.Is(err, ErrJournalDraining) || entered {
		t.Fatal("a second maintenance source ignored the first live activity", err)
	}
	if err := replica.WithDrainedInvalidation(operational, pending, allowActivityMaintenance, func(context.Context) error { entered = true; return nil }); !errors.Is(err, ErrJournalDraining) || entered {
		t.Fatal("lost SQL lease admitted destructive mutation before actual drain", err)
	}
	if _, err := replica.Lookup(f.blue.requestContext(t), f.blue.scope.ConversationID, Revision{MessageID: f.blue.scope.MessageID, Revision: f.blue.scope.Revision}, 1<<20, f.blue.authorizeHistory); err != nil {
		t.Fatal("held red matcher blocked independent blue history", err)
	}
	unblock()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("revoked/lost-lease matching reported clean success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual source join did not complete")
	}
	select {
	case <-childDone:
	case <-time.After(5 * time.Second):
		t.Fatal("nested source goroutine did not finish")
	}
	if f.active(t, f.red.scope.TenantID) != 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) || frozen.value.wire.Subject != "" {
		t.Fatal("actual matching buffer or registration survived return")
	}
	if err := replica.WithDrainedInvalidation(operational, pending, allowActivityMaintenance, func(context.Context) error { return nil }); err != nil {
		t.Fatal("actual drain could not resume the exact pending operation", err)
	}
}

func TestHistoryJournalPostgresSubjectPendingSourceRechecksFamilyAfterLeaseLoss(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedSubjectOperation(t, f.journal, f.red, time.Time{})
	seedSubjectOperation(t, f.journal, f.blue, time.Time{})
	pending := subjectOperationIntent(t, f)
	operational := f.operational(t, f.red.scope.TenantID)
	opened := false
	err := f.journal.withSubjectMatchSource(operational, f.red.codec, pending, allowActivityMaintenance, func(ctx context.Context, _ SubjectErasurePlan) error {
		var pid int
		if err := f.admin.QueryRow(t.Context(), `WITH lease_key AS(SELECT hashtextextended('probectl.flow_conversations.operation:'||$1::text,0) AS value)
 SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid,lease_key WHERE l.locktype='advisory' AND l.granted AND l.mode='ExclusiveLock' AND l.objsubid=1 AND l.classid=((lease_key.value>>32)&4294967295)::oid AND l.objid=(lease_key.value&4294967295)::oid AND a.datname=current_database() AND a.query LIKE '%probectl.flow_conversations.operation:%'`, f.red.scope.TenantID).Scan(&pid); err != nil {
			return err
		}
		var killed bool
		if err := f.admin.QueryRow(t.Context(), `SELECT pg_terminate_backend($1)`, pid).Scan(&killed); err != nil || !killed {
			return errors.New("owned exact family-lease fault failed")
		}
		if _, err := f.admin.Exec(t.Context(), `ALTER TABLE public.flow_conversation_messages NO FORCE ROW LEVEL SECURITY`); err != nil {
			return err
		}
		defer func() {
			if _, err := f.admin.Exec(t.Context(), `ALTER TABLE public.flow_conversation_messages FORCE ROW LEVEL SECURITY`); err != nil {
				t.Error("owned message posture restore failed", err)
			}
		}()
		readErr := visitSubjectOperationFixture(ctx, f.journal, f.red, func(_ context.Context, body []byte) error {
			opened = bytes.Contains(body, []byte("subject@example.test"))
			return nil
		})
		if readErr == nil || opened {
			t.Error("unknown message storage posture admitted authenticated source")
		}
		return readErr
	})
	if err == nil || opened || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("lost lease or malformed family reported healthy source/drain", err)
	}
	if _, err := f.journal.Lookup(f.blue.requestContext(t), f.blue.scope.ConversationID, Revision{MessageID: f.blue.scope.MessageID, Revision: f.blue.scope.Revision}, 1<<20, f.blue.authorizeHistory); err != nil {
		t.Fatal("restored family did not preserve independent blue history", err)
	}
}
