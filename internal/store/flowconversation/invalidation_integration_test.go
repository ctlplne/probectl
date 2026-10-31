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
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestHistoryJournalPostgresDurableInvalidation(t *testing.T) {
	admin, pool := journalFixture(t)
	if admin == nil {
		return
	}
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	blue := f
	blue.scope.TenantID = mustInvalidationUUID(t)
	blue.context = tenancy.WithTenant(t.Context(), tenancy.ID(blue.scope.TenantID))
	var err error
	blue.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, blue.scope.TenantID, blue.scope.OwnerID, blue.credentialID, blue.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{f.scope.TenantID, blue.scope.TenantID} {
		if _, err := admin.Exec(ctx, `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned invalidation fixture')`, tenant, "probectl-qa-beta-invalidation-"+strings.ReplaceAll(tenant, "-", "")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{f.scope.TenantID, blue.scope.TenantID}); err != nil {
			t.Error("owned invalidation tenant cleanup failed", err)
		}
	})
	journal := NewJournal(pool)
	allowSource := func(f messageCodecFixture) AuthorizeMessage {
		return func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
			return f.authorize(ctx, f.scope, origin, required)
		}
	}
	prepare := func(f messageCodecFixture, scope MessageScope) PreparedInput {
		t.Helper()
		input, err := f.codec.PrepareInput(f.requestContext(t), scope, inputMetadata(), []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"question":"private durable invalidation fixture"}`), allowSource(f))
		if err != nil {
			t.Fatal(err)
		}
		return input
	}
	redInput, blueInput := prepare(f, f.scope), prepare(blue, blue.scope)
	if err := journal.AdmitInput(ctx, redInput, allowSource(f)); err != nil {
		t.Fatal(err)
	}
	blueCtx := blue.requestContext(t)
	if err := journal.AdmitInput(blueCtx, blueInput, allowSource(blue)); err != nil {
		t.Fatal(err)
	}
	revision := Revision{MessageID: f.scope.MessageID, Revision: f.scope.Revision}
	worker, err := NewWorker(journal, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := worker.ClaimInput(ctx, f.scope.ConversationID, revision, f.authorizeHistory)
	if err != nil {
		t.Fatal(err)
	}
	source, err := journal.Lookup(ctx, f.scope.ConversationID, revision, 1<<20, f.authorizeHistory)
	if err != nil {
		t.Fatal(err)
	}
	proposalScope := f.scope
	proposalScope.MessageID = mustInvalidationUUID(t)
	meta := source.Metadata()
	meta.Parent = &revision
	proposal, err := f.codec.PrepareProposal(ctx, lease, source, proposalScope, meta, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"proposal":"private storage fixture"}`), allowSource(f))
	if err != nil {
		t.Fatal(err)
	}
	pendingScope := f.scope
	pendingScope.MessageID = mustInvalidationUUID(t)
	preparedBefore := prepare(f, pendingScope)
	// Three active jobs across two owners; the batch must not silently keep
	// the ordinary creator's owner filter during lifecycle maintenance.
	queuedScope := f.scope
	queuedScope.MessageID = mustInvalidationUUID(t)
	if err := journal.AdmitInput(ctx, prepare(f, queuedScope), allowSource(f)); err != nil {
		t.Fatal(err)
	}
	otherOwner := f
	otherOwner.scope.OwnerID = mustInvalidationUUID(t)
	otherOwner.scope.MessageID = mustInvalidationUUID(t)
	otherOwner.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, otherOwner.scope.TenantID, otherOwner.scope.OwnerID, otherOwner.credentialID, otherOwner.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.AdmitInput(otherOwner.requestContext(t), prepare(otherOwner, otherOwner.scope), allowSource(otherOwner)); err != nil {
		t.Fatal(err)
	}
	operational := tenancy.WithTenant(t.Context(), tenancy.ID(f.scope.TenantID))
	allow := func(ctx context.Context, tenant string) error {
		current, ok := tenancy.FromContext(ctx)
		if !ok || current.String() != tenant {
			return ErrMessageDenied
		}
		return ctx.Err()
	}
	request := maintenanceRequestFixture(f)
	auditCount := func() int {
		t.Helper()
		var n int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND action='flow.conversation.invalidate_intent'`, f.scope.TenantID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	original := journal.record
	journal.record = func(context.Context, tenancy.Scope, string, string, string, map[string]any) error {
		return errors.New("owned audit refusal")
	}
	failed, beginErr := journal.BeginInvalidation(operational, request, allow)
	journal.record = original
	if failed.value != nil || !errors.Is(beginErr, ErrJournalUnavailable) || auditCount() != 0 {
		t.Fatal("audit refusal produced durable invalidation", beginErr)
	}
	if generation, err := journal.CandidateEpoch(ctx); err != nil || generation != 1 {
		t.Fatal("failed audit advanced marker", err)
	}
	if err := worker.CheckLease(ctx, lease, f.authorizeHistory); err != nil {
		t.Fatal("failed intent canceled healthy worker", err)
	}
	// Signed counter overflow must refuse instead of wrapping a generation.
	if _, err := admin.Exec(ctx, `UPDATE flow_conversation_epochs SET generation=$2 WHERE tenant_id=$1::uuid`, f.scope.TenantID, int64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	if pending, err := journal.BeginInvalidation(operational, request, allow); pending.value != nil || !errors.Is(err, ErrJournalGeneration) {
		t.Fatal("epoch overflow advanced invalidation", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE flow_conversation_epochs SET generation=1 WHERE tenant_id=$1::uuid`, f.scope.TenantID); err != nil {
		t.Fatal(err)
	}
	type beginning struct {
		pending Invalidation
		err     error
	}
	started := make(chan beginning, 2)
	for range 2 {
		go func() {
			pending, err := NewJournal(pool).BeginInvalidation(operational, request, allow)
			started <- beginning{pending, err}
		}()
	}
	first, second := <-started, <-started
	pending, err := first.pending, first.err
	if err != nil || second.err != nil || pending.value == nil || second.pending.value == nil || *pending.value != *second.pending.value || pending.value.generation != 2 || auditCount() != 1 {
		t.Fatal("competing exact intent starts did not commit one immutable transition", err, second.err)
	}
	for _, change := range []func(*MaintenanceRequest){func(r *MaintenanceRequest) { r.ID = mustInvalidationUUID(t) }, func(r *MaintenanceRequest) { r.Kind = MaintenanceRetention }, func(r *MaintenanceRequest) { r.Binding[31] = 4 }} {
		other := request
		change(&other)
		if value, err := NewJournal(pool).BeginInvalidation(operational, other, allow); value.value != nil || !errors.Is(err, ErrJournalConflict) {
			t.Fatal("different lifecycle plan adopted pending intent", err)
		}
	}
	resumed, err := NewJournal(pool).BeginInvalidation(operational, request, allow)
	if err != nil || resumed.value == nil || *resumed.value != *pending.value || auditCount() != 1 {
		t.Fatal("exact retry duplicated or changed the durable intent", err)
	}
	for _, operation := range []func() error{
		func() error { _, err := journal.CandidateEpoch(ctx); return err },
		func() error {
			_, err := journal.Lookup(ctx, f.scope.ConversationID, revision, 1<<20, f.authorizeHistory)
			return err
		},
		func() error {
			_, err := journal.Page(ctx, f.scope.ConversationID, nil, HistoryBudget{Rows: 1, Bytes: 1 << 20}, f.authorizeHistory)
			return err
		},
		func() error { return journal.AdmitInput(ctx, preparedBefore, allowSource(f)) },
		func() error {
			_, err := worker.ClaimInput(ctx, f.scope.ConversationID, revision, f.authorizeHistory)
			return err
		},
		func() error { _, err := worker.Renew(ctx, lease, f.authorizeHistory); return err },
		func() error { return journal.CancelInput(ctx, f.scope.ConversationID, revision, f.authorizeHistory) },
		func() error { _, err := worker.PublishProposal(ctx, lease, proposal, allowSource(f)); return err },
		func() error {
			_, err := journal.DispatchPage(operational, f.scope.OwnerID, nil, DispatchBudget{Rows: 1, HeaderBytes: 1 << 20, TimeLimit: time.Second}, f.authorizeDispatch)
			return err
		},
		func() error {
			return journal.WithReadLease(ctx, f.authorizeHistory, func(context.Context) error {
				t.Error("invalidating tenant entered ordinary source callback")
				return nil
			})
		},
	} {
		if err := operation(); !errors.Is(err, ErrJournalGeneration) {
			t.Fatal("ordinary history operation bypassed durable invalidation", err)
		}
	}
	if err := worker.CheckLease(ctx, lease, f.authorizeHistory); !errors.Is(err, ErrJournalLease) {
		t.Fatal("invalidating epoch retained a live worker fence", err)
	}
	blueRecord, err := journal.Lookup(blueCtx, blue.scope.ConversationID, revision, 1<<20, blue.authorizeHistory)
	if err != nil || blueRecord.Scope().TenantID != blue.scope.TenantID {
		t.Fatal("red invalidation refused or crossed healthy blue source", err)
	}
	if value, err := journal.ResumeInvalidation(tenancy.WithTenant(t.Context(), tenancy.ID(blue.scope.TenantID)), request, allow); value.value != nil || !errors.Is(err, ErrJournalConflict) {
		t.Fatal("red intent resumed in blue tenant", err)
	}
	t.Run("bounded counted cancellation preserves intent and source", func(t *testing.T) {
		active := func() int64 {
			t.Helper()
			var n int64
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND status IN ('queued','processing')`, f.scope.TenantID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		if active() != 3 {
			t.Fatal("owned three-job fixture incomplete")
		}
		budget := CancellationBudget{Rows: 1, TimeLimit: time.Second}
		original := journal.record
		journal.record = func(context.Context, tenancy.Scope, string, string, string, map[string]any) error {
			return errors.New("owned cancellation audit refusal")
		}
		batch, cancelErr := journal.CancelInvalidated(operational, pending, budget, allow)
		journal.record = original
		if batch != (CancellationBatch{}) || !errors.Is(cancelErr, ErrJournalUnavailable) || active() != 3 {
			t.Fatal("cancellation audit failure committed partial metadata", cancelErr)
		}
		if _, err := admin.Exec(ctx, `UPDATE flow_conversation_jobs SET cancel_revision=$2 WHERE tenant_id=$1::uuid AND status IN ('queued','processing')`, f.scope.TenantID, int64(math.MaxInt64)); err != nil {
			t.Fatal(err)
		}
		if batch, err := journal.CancelInvalidated(operational, pending, budget, allow); batch != (CancellationBatch{}) || !errors.Is(err, ErrJournalGeneration) || active() != 3 {
			t.Fatal("cancellation counter overflow wrapped or partially advanced jobs", err)
		}
		if _, err := admin.Exec(ctx, `UPDATE flow_conversation_jobs SET cancel_revision=0 WHERE tenant_id=$1::uuid AND status IN ('queued','processing')`, f.scope.TenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `REVOKE SELECT ON flow_conversation_messages FROM probectl_app`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := admin.Exec(cleanup, `GRANT SELECT ON flow_conversation_messages TO probectl_app`); err != nil {
				t.Error("owned source SELECT restore failed", err)
			}
		})
		for i := int64(0); i < 3; i++ {
			batch, err := journal.CancelInvalidated(operational, pending, budget, allow)
			if err != nil || batch.Canceled != 1 || batch.ActiveRemaining != 2-i || active() != 2-i {
				t.Fatal("bounded cancellation lost complete active-job accounting", err, batch.Canceled, batch.ActiveRemaining)
			}
		}
		if batch, err := journal.CancelInvalidated(operational, pending, budget, allow); err != nil || batch != (CancellationBatch{}) {
			t.Fatal("empty repeat manufactured work or failed", err)
		}
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND action='flow.conversation.cancel_invalidated'`, f.scope.TenantID).Scan(&count); err != nil || count != 3 {
			t.Fatal("bounded cancellation audit count changed", err, count)
		}
		var blueActive int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND status='queued'`, blue.scope.TenantID).Scan(&blueActive); err != nil || blueActive != 1 {
			t.Fatal("red cancellation touched blue work", err)
		}
		if _, err := journal.CandidateEpoch(ctx); !errors.Is(err, ErrJournalGeneration) {
			t.Fatal("zero active jobs cleared pending lifecycle intent", err)
		}
	})
	// Pending reference is not a completion capability. Failures/timeouts leave
	// the intent present, including across a fresh Journal and offboarding.
	callbackError := errors.New("owned unfinished counted cleanup")
	if err := journal.WithInvalidationLease(operational, pending, allow, func(context.Context) error { return callbackError }); !errors.Is(err, callbackError) {
		t.Fatal("pending maintenance changed bounded callback error", err)
	}
	if _, err := admin.Exec(ctx, `REVOKE SELECT ON flow_conversation_messages,flow_conversation_jobs FROM probectl_app`); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `GRANT SELECT ON flow_conversation_messages,flow_conversation_jobs TO probectl_app`); err != nil {
			t.Error("owned source permission restore failed", err)
		}
	}
	t.Cleanup(restore)
	if _, err := admin.Exec(ctx, `UPDATE tenants SET status='offboarding' WHERE id=$1::uuid`, f.scope.TenantID); err != nil {
		t.Fatal(err)
	}
	resumed, err = NewJournal(pool).ResumeInvalidation(operational, request, allow)
	if err != nil || resumed.value == nil || *resumed.value != *pending.value {
		t.Fatal("source-free restart could not resume exact offboarding intent", err)
	}
	entered := false
	if err := NewJournal(pool).WithInvalidationLease(operational, resumed, allow, func(context.Context) error { entered = true; return nil }); err != nil || !entered {
		t.Fatal("exact independently authorized metadata maintenance failed without source SELECT", err)
	}
	if value, err := journal.ResumeInvalidation(operational, request, func(context.Context, string) error { return ErrMessageDenied }); value.value != nil || !errors.Is(err, ErrMessageDenied) {
		t.Fatal("revoked operational authority resumed intent", err)
	}
	if _, err := journal.CandidateEpoch(ctx); !errors.Is(err, ErrJournalGeneration) {
		t.Fatal("successful metadata callback cleared unverified invalidation", err)
	}

	t.Run("lease connection loss cannot clear durable refusal", func(t *testing.T) {
		replicaPool, err := pgxpool.NewWithConfig(t.Context(), pool.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(replicaPool.Close)
		replica := NewJournal(replicaPool)
		started, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{})
		finished := make(chan error, 1)
		leaseCtx, stop := context.WithTimeout(operational, 5*time.Second)
		var released bool
		releaseCallback := func() {
			if !released {
				released = true
				close(release)
			}
		}
		go func() {
			defer close(ended)
			finished <- journal.WithInvalidationLease(leaseCtx, pending, allow, func(context.Context) error { close(started); <-release; return nil })
		}()
		t.Cleanup(func() {
			stop()
			releaseCallback()
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Error("owned lost-connection callback did not drain")
			}
		})
		select {
		case <-started:
		case err := <-finished:
			t.Fatal("owned maintenance did not start", err)
		case <-time.After(5 * time.Second):
			t.Fatal("owned maintenance start timed out")
		}
		var pid int
		if err := admin.QueryRow(ctx, `WITH lease_key AS(SELECT hashtextextended('probectl.flow_conversations.operation:' || $1::text,0) AS value)
    SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid,lease_key
    WHERE l.locktype='advisory' AND l.granted AND l.mode='ExclusiveLock' AND l.objsubid=1
      AND l.classid=((lease_key.value>>32)&4294967295)::oid AND l.objid=(lease_key.value&4294967295)::oid
      AND a.datname=current_database() AND a.query LIKE '%probectl.flow_conversations.operation:%'`, f.scope.TenantID).Scan(&pid); err != nil {
			t.Fatal("exact owned lease backend was not observed", err)
		}
		var killed bool
		if err := admin.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&killed); err != nil || !killed {
			t.Fatal("owned lease backend fault injection failed", err)
		}
		// A different pool may read the durable intent even while this callback is
		// deliberately still running. This proves refusal persistence, not drain.
		if value, err := replica.ResumeInvalidation(operational, request, allow); err != nil || value.value == nil || *value.value != *pending.value {
			t.Fatal("lease connection loss lost the durable pending intent", err)
		}
		if _, err := replica.CandidateEpoch(ctx); !errors.Is(err, ErrJournalGeneration) {
			t.Fatal("lost advisory lock revived ordinary history work", err)
		}
		select {
		case err := <-finished:
			t.Fatal("cancellation/lost connection stood in for actual callback return", err)
		default:
		}
		releaseCallback()
		select {
		case err := <-finished:
			if !errors.Is(err, ErrJournalUnavailable) {
				t.Fatal("lost lease transaction returned successful maintenance", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("released lost-connection callback did not return")
		}
		if value, err := replica.ResumeInvalidation(operational, request, allow); err != nil || value.value == nil {
			t.Fatal("failed lease auto-cleared unverified intent", err)
		}
	})
}

func mustInvalidationUUID(t *testing.T) string {
	t.Helper()
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
