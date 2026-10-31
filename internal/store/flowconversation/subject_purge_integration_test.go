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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

func prepareSubjectPurge(t *testing.T, f activityFixture, pending Invalidation) subjectLeafSelection {
	t.Helper()
	ctx := f.operational(t, f.red.scope.TenantID)
	for {
		batch, err := f.journal.CancelInvalidated(ctx, pending, CancellationBudget{Rows: 8, TimeLimit: 5 * time.Second}, allowActivityMaintenance)
		if err != nil {
			t.Fatal(err)
		}
		if batch.ActiveRemaining == 0 {
			break
		}
		if batch.Canceled == 0 {
			t.Fatal("owned job cancellation made no progress")
		}
	}
	probe := &subjectSelectionProbe{}
	selection, err := f.journal.selectSubjectLeaves(ctx, f.red.codec, pending, HistoryBudget{Rows: 16, Bytes: 1 << 20}, allowActivityMaintenance, probe.factory)
	if err != nil || len(selection.leaves) == 0 || selection.pending.value == nil || *selection.pending.value != *pending.value {
		t.Fatal("exact pending leaf selection failed", err)
	}
	probe.assertDrained(t, f)
	return selection
}

func subjectPurgeCounts(t *testing.T, f activityFixture) [2]int64 {
	t.Helper()
	var counts [2]int64
	if err := f.admin.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM flow_conversation_messages WHERE tenant_id=$1::uuid),(SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid)`, f.red.scope.TenantID).Scan(&counts[0], &counts[1]); err != nil {
		t.Fatal(err)
	}
	return counts
}

func subjectPurgeAuditCount(t *testing.T, f activityFixture) int {
	t.Helper()
	var n int
	if err := f.admin.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND action='flow.conversation.subject_purge'`, f.red.scope.TenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHistoryJournalPostgresSubjectPurgeBoundedProposalReferences(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedSubjectOperation(t, f.journal, f.blue, time.Time{})
	parent := seedSelectionMetadata(t, f.journal, f.red, "neutral original input", inputMetadata())
	ctx := parent.requestContext(t)
	worker, err := NewWorker(f.journal, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ref := Revision{MessageID: parent.scope.MessageID, Revision: parent.scope.Revision}
	lease, err := worker.ClaimInput(ctx, parent.scope.ConversationID, ref, parent.authorizeHistory)
	if err != nil {
		t.Fatal(err)
	}
	input, err := f.journal.Lookup(ctx, parent.scope.ConversationID, ref, 1<<20, parent.authorizeHistory)
	if err != nil {
		t.Fatal(err)
	}
	proposal := parent
	proposal.scope.MessageID = mustInvalidationUUID(t)
	meta := input.Metadata()
	meta.Parent = &ref
	check := func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
		return parent.authorize(ctx, parent.scope, origin, required)
	}
	prepared, err := parent.codec.PrepareProposal(ctx, lease, input, proposal.scope, meta, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"question":"subject@example.test"}`), check)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.PublishProposal(ctx, lease, prepared, check); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		other := f.red
		other.scope.MessageID = mustInvalidationUUID(t)
		seedSelectionMetadata(t, f.journal, other, "neutral reference input", inputMetadata())
		// The proposal FK is intentionally non-unique. Exercise actual SQL
		// references without claiming these generic fixtures are native jobs.
		if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_jobs SET proposal_message_id=$3::uuid,proposal_revision=$4 WHERE tenant_id=$1::uuid AND input_message_id=$2::uuid`, other.scope.TenantID, other.scope.MessageID, proposal.scope.MessageID, int64(proposal.scope.Revision)); err != nil {
			t.Fatal(err)
		}
	}
	pending := subjectSelectionIntent(t, f, nil)
	selection := prepareSubjectPurge(t, f, pending)
	if len(selection.leaves) != 1 || selection.leaves[0].Scope() != proposal.scope || selection.leaves[0].Kind() != "proposal" {
		t.Fatal("actual published proposal was not the selected leaf")
	}
	before := subjectPurgeCounts(t, f)
	if before != [2]int64{6, 5} {
		t.Fatal("many-reference fixture was not established", before)
	}
	tenantcrypto.Reset() // deletion must not decrypt the already matched source
	defer tenantcrypto.SetPrimary(f.red.sealer)
	for i := range 5 {
		batch, err := f.journal.purgeSubjectLeaf(f.operational(t, f.red.scope.TenantID), selection, 0, CancellationBudget{Rows: 1, TimeLimit: 5 * time.Second}, allowActivityMaintenance)
		wantMessages := int64(0)
		if i == 4 {
			wantMessages = 1
		}
		if err != nil || batch.jobsDeleted != 1 || batch.messagesDeleted != wantMessages || batch.referencesRemaining != int64(4-i) || batch.jobsRemaining != int64(4-i) || batch.messagesRemaining != 6-wantMessages {
			t.Fatal("job budget1 admitted a cascade or lost exact physical counts", batch, err)
		}
		if subjectPurgeAuditCount(t, f) != i+1 {
			t.Fatal("counted progress lacked its atomic audit")
		}
	}
	if subjectPurgeCounts(t, f) != [2]int64{5, 0} {
		t.Fatal("unrelated inputs were cascaded with their shared proposal")
	}
	if batch, err := f.journal.purgeSubjectLeaf(f.operational(t, f.red.scope.TenantID), selection, 0, CancellationBudget{Rows: 1, TimeLimit: 5 * time.Second}, allowActivityMaintenance); !errors.Is(err, ErrJournalConflict) || batch != (subjectPurgeBatch{}) || subjectPurgeAuditCount(t, f) != 5 {
		t.Fatal("stale/uncertain work item was assumed to have completed", err)
	}
	tenantcrypto.SetPrimary(f.red.sealer)
	probe := &subjectSelectionProbe{}
	remaining, err := f.journal.selectSubjectLeaves(f.operational(t, f.red.scope.TenantID), f.red.codec, pending, HistoryBudget{Rows: 2, Bytes: 1 << 20}, allowActivityMaintenance, probe.factory)
	if err != nil || !remaining.exhausted || remaining.scanned != 5 || len(remaining.leaves) != 0 {
		t.Fatal("fresh complete scan did not verify remaining unrelated inputs", err)
	}
	probe.assertDrained(t, f)
}

func TestHistoryJournalPostgresSubjectPurgeExactPairsAuditAndCounts(t *testing.T) {
	for _, fault := range []string{"header", "payload", "pair", "metadata", "new_child", "generation", "binding", "audit_failure", "delete_trigger_drift", "audit_appender_drift"} {
		t.Run(fault, func(t *testing.T) {
			f := newActivityFixture(t)
			if f.admin == nil {
				return
			}
			seedSubjectOperation(t, f.journal, f.red, time.Time{})
			seedSubjectOperation(t, f.journal, f.blue, time.Time{})
			other := f.red
			other.scope.MessageID = mustInvalidationUUID(t)
			seedSelectionMetadata(t, f.journal, other, "neutral unrelated", inputMetadata())
			pending := subjectSelectionIntent(t, f, nil)
			selection := prepareSubjectPurge(t, f, pending)
			target := selection.leaves[0]
			want := ErrJournalConflict
			switch fault {
			case "header", "payload", "pair":
				fresh := f.red.seal(t, []byte(`{"question":"subject@example.test"}`))
				header, payload := target.Ciphertext().parts.header, target.Ciphertext().parts.payload
				if fault != "payload" {
					header = fresh.parts.header
				}
				if fault != "header" {
					payload = fresh.parts.payload
				}
				if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_messages SET private_header=$3,private_payload=$4 WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, f.red.scope.TenantID, f.red.scope.MessageID, header, payload); err != nil {
					t.Fatal(err)
				}
			case "metadata":
				if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_messages SET frozen_at=$3 WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, f.red.scope.TenantID, f.red.scope.MessageID, target.Metadata().FrozenAt.Add(-time.Second).Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			case "new_child":
				child := f.red
				child.scope.MessageID = mustInvalidationUUID(t)
				sealed := child.seal(t, []byte(`{"question":"neutral new child"}`))
				if _, err := f.admin.Exec(t.Context(), `INSERT INTO flow_conversation_messages SELECT tenant_id,owner_id,conversation_id,$3::uuid,1,epoch,message_id,revision,'input',frozen_at,expires_at,$4,$5,position+100 FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, f.red.scope.TenantID, f.red.scope.MessageID, child.scope.MessageID, sealed.parts.header, sealed.parts.payload); err != nil {
					t.Fatal(err)
				}
			case "generation":
				if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_epochs SET generation=generation+1 WHERE tenant_id=$1::uuid`, f.red.scope.TenantID); err != nil {
					t.Fatal(err)
				}
				want = ErrJournalGeneration
			case "binding":
				if _, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_epochs SET operation_binding=$2 WHERE tenant_id=$1::uuid`, f.red.scope.TenantID, bytes.Repeat([]byte{9}, 32)); err != nil {
					t.Fatal(err)
				}
			case "audit_failure", "audit_appender_drift":
				original := f.journal.record
				defer func() { f.journal.record = original }()
				f.journal.record = func(ctx context.Context, sc tenancy.Scope, actor, action, target string, data map[string]any) error {
					if action != "flow.conversation.subject_purge" {
						return original(ctx, sc, actor, action, target, data)
					}
					if fault == "audit_failure" {
						return errors.New("owned subject purge audit refusal")
					}
					if err := original(ctx, sc, actor, action, target, data); err != nil {
						return err
					}
					_, err := sc.Q.Exec(ctx, `DELETE FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, other.scope.TenantID, other.scope.MessageID)
					return err
				}
				if fault == "audit_failure" {
					want = ErrJournalUnavailable
				}
			case "delete_trigger_drift":
				name := "probectl_qa_beta_subject_" + strings.ReplaceAll(mustInvalidationUUID(t), "-", "")
				function, trigger := pgx.Identifier{"public", name}.Sanitize(), pgx.Identifier{name}.Sanitize()
				if _, err := f.admin.Exec(t.Context(), `CREATE FUNCTION `+function+`() RETURNS trigger LANGUAGE plpgsql AS $owned$ BEGIN IF OLD.message_id='`+f.red.scope.MessageID+`'::uuid THEN DELETE FROM public.flow_conversation_messages WHERE tenant_id=OLD.tenant_id AND message_id='`+other.scope.MessageID+`'::uuid; END IF; RETURN OLD; END $owned$`); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if _, err := f.admin.Exec(cleanup, `DROP TRIGGER IF EXISTS `+trigger+` ON public.flow_conversation_messages; DROP FUNCTION `+function+`() `); err != nil {
						t.Error("owned subject trigger cleanup failed", err)
					}
				})
				if _, err := f.admin.Exec(t.Context(), `CREATE TRIGGER `+trigger+` AFTER DELETE ON public.flow_conversation_messages FOR EACH ROW EXECUTE FUNCTION `+function+`() `); err != nil {
					t.Fatal(err)
				}
			}
			before := subjectPurgeCounts(t, f)
			batch, err := f.journal.purgeSubjectLeaf(f.operational(t, f.red.scope.TenantID), selection, 0, CancellationBudget{Rows: 1, TimeLimit: 5 * time.Second}, allowActivityMaintenance)
			if !errors.Is(err, want) || batch != (subjectPurgeBatch{}) || subjectPurgeCounts(t, f) != before || subjectPurgeAuditCount(t, f) != 0 || f.active(t, f.red.scope.TenantID) != 0 {
				t.Fatal("changed source/intent/audit/counts escaped atomic refusal", err)
			}
			if _, err := f.journal.Lookup(f.blue.requestContext(t), f.blue.scope.ConversationID, Revision{MessageID: f.blue.scope.MessageID, Revision: f.blue.scope.Revision}, 1<<20, f.blue.authorizeHistory); err != nil {
				t.Fatal("red refusal damaged sibling history", err)
			}
		})
	}
}

func TestHistoryJournalPostgresSubjectPurgeExpiredInheritedClosure(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedSubjectOperation(t, f.journal, f.blue, time.Time{})
	expires := time.Now().Add(2 * time.Second)
	_, mid, _ := seedSelectionChain(t, f, expires)
	branch := f.red
	branch.scope.MessageID = selectionFixtureID(9)
	seedSelectionMetadata(t, f.journal, branch, "neutral branch", InputMetadata{FrozenAt: time.Now().UTC(), ExpiresAt: expires, Parent: &Revision{MessageID: mid.scope.MessageID, Revision: mid.scope.Revision}})
	unrelated := f.red
	unrelated.scope.MessageID = selectionFixtureID(0)
	seedSelectionMetadata(t, f.journal, unrelated, "neutral unrelated", inputMetadata())
	pending := subjectSelectionIntent(t, f, nil)
	prepareSubjectPurge(t, f, pending)
	select {
	case <-time.After(time.Until(expires) + 10*time.Millisecond):
	case <-t.Context().Done():
		t.Fatal("owned expiry wait canceled")
	}
	var messages, jobs int64
	for range 4 {
		probe := &subjectSelectionProbe{}
		selection, err := f.journal.selectSubjectLeaves(f.operational(t, f.red.scope.TenantID), f.red.codec, pending, HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, probe.factory)
		if err != nil || len(selection.leaves) != 1 || !selection.leaves[0].Metadata().ExpiresAt.Before(time.Now()) {
			t.Fatal("expired branch/ancestor escaped complete repeated selection", err)
		}
		probe.assertDrained(t, f)
		batch, err := f.journal.purgeSubjectLeaf(f.operational(t, f.red.scope.TenantID), selection, 0, CancellationBudget{Rows: 1, TimeLimit: 5 * time.Second}, allowActivityMaintenance)
		if err != nil || batch.messagesDeleted != 1 || batch.jobsDeleted != 1 {
			t.Fatal("bounded inherited leaf deletion failed", err)
		}
		messages += batch.messagesDeleted
		jobs += batch.jobsDeleted
	}
	probe := &subjectSelectionProbe{}
	remaining, err := f.journal.selectSubjectLeaves(f.operational(t, f.red.scope.TenantID), f.red.codec, pending, HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, probe.factory)
	if err != nil || !remaining.exhausted || remaining.scanned != 1 || len(remaining.leaves) != 0 || messages != 4 || jobs != 4 || subjectPurgeCounts(t, f) != [2]int64{1, 1} {
		t.Fatal("physical counts did not preserve unrelated private data", err)
	}
	probe.assertDrained(t, f)
}

type subjectPurgePausedFence struct {
	next             tenancy.WriterFence
	started, release chan struct{}
}

func (f *subjectPurgePausedFence) WithTenantWrites(ctx context.Context, tenants []string, fn func(context.Context) error) error {
	close(f.started)
	select {
	case <-f.release:
		return f.next.WithTenantWrites(ctx, tenants, fn)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestHistoryJournalPostgresSubjectPurgeRechecksDrainAfterLeaseLoss(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedSubjectOperation(t, f.journal, f.red, time.Time{})
	seedSubjectOperation(t, f.journal, f.blue, time.Time{})
	pending := subjectSelectionIntent(t, f, nil)
	selection := prepareSubjectPurge(t, f, pending)
	before := subjectPurgeCounts(t, f)
	pool, err := pgxpool.NewWithConfig(t.Context(), f.pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	paused := &subjectPurgePausedFence{next: f.journal.fence, started: make(chan struct{}), release: make(chan struct{})}
	f.journal.fence = paused
	resume := sync.OnceFunc(func() { close(paused.release) })
	sourceRelease := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(sourceRelease) })
	purgeDone, sourceDone := make(chan struct{}), make(chan struct{})
	var sourceStarted bool
	t.Cleanup(func() {
		resume()
		unblock()
		select {
		case <-purgeDone:
		case <-time.After(5 * time.Second):
			t.Error("owned purge goroutine did not drain")
		}
		f.journal.fence = paused.next
		if sourceStarted {
			select {
			case <-sourceDone:
			case <-time.After(5 * time.Second):
				t.Error("owned actual source goroutine did not drain")
			}
		}
	})
	purgeResult := make(chan error, 1)
	go func() {
		defer close(purgeDone)
		_, err := f.journal.purgeSubjectLeaf(f.operational(t, f.red.scope.TenantID), selection, 0, CancellationBudget{Rows: 1, TimeLimit: 10 * time.Second}, allowActivityMaintenance)
		purgeResult <- err
	}()
	select {
	case <-paused.started: // outer zero-activity check already passed
	case <-time.After(5 * time.Second):
		t.Fatal("purge did not reach the pre-writer boundary")
	}
	var pid int
	if err := f.admin.QueryRow(t.Context(), `WITH lease_key AS(SELECT hashtextextended('probectl.flow_conversations.operation:'||$1::text,0) AS value)
 SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid,lease_key WHERE l.locktype='advisory' AND l.granted AND l.mode='ExclusiveLock' AND l.objsubid=1 AND l.classid=((lease_key.value>>32)&4294967295)::oid AND l.objid=(lease_key.value&4294967295)::oid AND a.datname=current_database() AND a.query LIKE '%probectl.flow_conversations.operation:%'`, f.red.scope.TenantID).Scan(&pid); err != nil {
		t.Fatal("owned exact purge family lease was not positively observed", err)
	}
	var killed bool
	if err := f.admin.QueryRow(t.Context(), `SELECT pg_terminate_backend($1)`, pid).Scan(&killed); err != nil || !killed {
		t.Fatal("owned exact purge family fault failed", err)
	}
	replica := NewJournal(pool)
	opened := make(chan struct{})
	var borrowed []byte
	sourceResult := make(chan error, 1)
	sourceStarted = true
	go func() {
		defer close(sourceDone)
		sourceResult <- replica.withSubjectMatchSource(f.operational(t, f.red.scope.TenantID), f.red.codec, pending, allowActivityMaintenance, func(ctx context.Context, _ SubjectErasurePlan) error {
			return visitSubjectOperationFixture(ctx, replica, f.red, func(_ context.Context, body []byte) error {
				borrowed = body
				close(opened)
				<-sourceRelease
				return nil
			})
		})
	}()
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("new actual source was not admitted after the owned lease fault")
	}
	if !bytes.Contains(borrowed, []byte("subject@example.test")) || f.active(t, f.red.scope.TenantID) != 1 {
		t.Fatal("new source did not hold a real body and durable activity")
	}
	resume()
	select {
	case err := <-purgeResult:
		if !errors.Is(err, ErrJournalDraining) || subjectPurgeCounts(t, f) != before || subjectPurgeAuditCount(t, f) != 0 {
			t.Fatal("eventual outer failure hid deletion before actual drain", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fresh in-transaction activity check did not refuse")
	}
	<-purgeDone
	f.journal.fence = paused.next
	unblock()
	select {
	case err := <-sourceResult:
		if err != nil {
			t.Fatal("owned matching callback could not finish", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual held body did not drain")
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("actual body drain was acknowledged prematurely")
	}
	batch, err := f.journal.purgeSubjectLeaf(f.operational(t, f.red.scope.TenantID), selection, 0, CancellationBudget{Rows: 1, TimeLimit: 5 * time.Second}, allowActivityMaintenance)
	if err != nil || batch.messagesDeleted != 1 || batch.jobsDeleted != 1 {
		t.Fatal("exact unchanged selection could not retry after actual drain", err)
	}
}
