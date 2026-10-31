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
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestHistoryJournalPostgresSubjectWorkflowDurableCountsAndRestart(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedSubjectOperation(t, f.journal, f.blue, time.Time{})
	seedSelectionChain(t, f, time.Now().Add(time.Hour))
	neutral := f.red
	neutral.scope.MessageID = selectionFixtureID(1)
	seedSelectionMetadata(t, f.journal, neutral, "neutral retained input", inputMetadata())
	pending := subjectSelectionIntent(t, f, nil)
	ctx := f.operational(t, f.red.scope.TenantID)
	probe := &subjectSelectionProbe{}
	progress, err := f.journal.PurgeSubjectHistory(ctx, f.red.codec, pending, HistoryBudget{Rows: 1, Bytes: 1 << 20}, CancellationBudget{Rows: 1, TimeLimit: 5 * time.Second}, allowActivityMaintenance, probe.factory)
	if err != nil || !progress.SourceEmpty || progress.MessagesDeleted != 3 || progress.JobsDeleted != 3 {
		t.Fatal("physical workflow lost complete ancestry/counts", err, progress.MessagesDeleted, progress.JobsDeleted, progress.SourceEmpty)
	}
	probe.assertDrained(t, f)
	if counts := subjectPurgeCounts(t, f); counts != [2]int64{1, 1} {
		t.Fatal("workflow removed unrelated source", counts)
	}
	restarted := NewJournal(f.journal.pool)
	installed, operation, err := restarted.SubjectErasureState(ctx, allowActivityMaintenance)
	if err != nil || !installed || operation != pending.value.request.ID {
		t.Fatal("restart lost exact pending operation", err)
	}
	got, err := restarted.ReadSubjectProgress(ctx, pending, allowActivityMaintenance)
	if err != nil || got != progress {
		t.Fatal("restart guessed/doubled durable counts", err)
	}
	got, err = restarted.PurgeSubjectHistory(ctx, f.red.codec, pending, HistoryBudget{Rows: 1, Bytes: 1 << 20}, CancellationBudget{Rows: 1, TimeLimit: 5 * time.Second}, allowActivityMaintenance, probe.factory)
	if err != nil || got != progress {
		t.Fatal("physical retry changed durable progress", err)
	}
	if _, _, err := restarted.SubjectErasureState(ctx, nil); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("metadata discovery borrowed absent current authority", err)
	}
}

type subjectCommitReplyLoss struct {
	next tenancy.WriterFence
	lost bool
}

func (f *subjectCommitReplyLoss) WithTenantWrites(ctx context.Context, tenants []string, fn func(context.Context) error) error {
	err := f.next.WithTenantWrites(ctx, tenants, fn)
	if err == nil && !f.lost {
		f.lost = true
		return errors.New("owned post-commit response loss")
	}
	return err
}

func TestHistoryJournalPostgresSubjectProgressRecoversCommittedReplyLoss(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedSubjectOperation(t, f.journal, f.blue, time.Time{})
	seedSelectionChain(t, f, time.Now().Add(time.Hour))
	pending := subjectSelectionIntent(t, f, nil)
	selection := prepareSubjectPurge(t, f, pending)
	ctx := f.operational(t, f.red.scope.TenantID)
	original := f.journal.fence
	lost := &subjectCommitReplyLoss{next: original}
	f.journal.fence = lost
	_, err := f.journal.purgeSubjectLeaf(ctx, selection, 0, CancellationBudget{Rows: 1, TimeLimit: 5 * time.Second}, allowActivityMaintenance)
	f.journal.fence = original
	if err == nil || !lost.lost {
		t.Fatal("owned committed-response loss was not exercised", err)
	}
	got, err := NewJournal(f.journal.pool).ReadSubjectProgress(ctx, pending, allowActivityMaintenance)
	if err != nil || got.MessagesDeleted != 1 || got.JobsDeleted != 1 || got.SourceEmpty {
		t.Fatal("uncertain commit could not recover actual durable progress", err, got.MessagesDeleted, got.JobsDeleted)
	}
	probe := &subjectSelectionProbe{}
	final, err := f.journal.PurgeSubjectHistory(ctx, f.red.codec, pending, HistoryBudget{Rows: 1, Bytes: 1 << 20}, CancellationBudget{Rows: 1, TimeLimit: 5 * time.Second}, allowActivityMaintenance, probe.factory)
	if err != nil || final.MessagesDeleted != 3 || final.JobsDeleted != 3 || !final.SourceEmpty {
		t.Fatal("uncertain retry double-added or lost exact committed counts", err, final.MessagesDeleted, final.JobsDeleted)
	}
	probe.assertDrained(t, f)
}

func TestHistoryJournalPostgresSubjectProgressAuditDriftRollsBack(t *testing.T) {
	for _, phase := range []string{"approval", "purge", "empty"} {
		t.Run(phase, func(t *testing.T) {
			f := newActivityFixture(t)
			if f.admin == nil {
				return
			}
			seedSubjectOperation(t, f.journal, f.blue, time.Time{})
			if phase == "purge" {
				seedSelectionChain(t, f, time.Now().Add(time.Hour))
			}
			ctx := f.operational(t, f.red.scope.TenantID)
			var pending Invalidation
			if phase != "approval" {
				pending = subjectSelectionIntent(t, f, nil)
			}
			original := f.journal.record
			defer func() { f.journal.record = original }()
			f.journal.record = func(ctx context.Context, sc tenancy.Scope, actor, action, target string, data map[string]any) error {
				if err := original(ctx, sc, actor, action, target, data); err != nil {
					return err
				}
				var query string
				switch {
				case phase == "approval" && action == "flow.conversation.invalidate_intent":
					query = `UPDATE flow_conversation_epochs SET operation_messages_deleted=1 WHERE tenant_id=$1::uuid`
				case phase == "purge" && action == "flow.conversation.subject_purge":
					query = `UPDATE flow_conversation_epochs SET operation_jobs_deleted=operation_jobs_deleted+1 WHERE tenant_id=$1::uuid`
				case phase == "empty" && action == "flow.conversation.subject_source_empty":
					query = `UPDATE flow_conversation_epochs SET operation_source_empty=false WHERE tenant_id=$1::uuid`
				}
				if query != "" {
					_, err := sc.Q.Exec(ctx, query, sc.Tenant.String())
					return err
				}
				return nil
			}
			if phase == "approval" {
				plan, err := f.red.codec.PrepareSubjectErasurePlan(ctx, mustInvalidationUUID(t), "subject@example.test", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer plan.Release()
				if _, err := f.journal.BeginSubjectInvalidation(ctx, f.red.codec, plan, allowActivityMaintenance); !errors.Is(err, ErrJournalConflict) {
					t.Fatal("approval accepted fabricated initial physical counts", err)
				}
				var pending int
				if err := f.admin.QueryRow(t.Context(), `SELECT count(*) FROM flow_conversation_epochs WHERE tenant_id=$1::uuid AND invalidating`, f.red.scope.TenantID).Scan(&pending); err != nil || pending != 0 {
					t.Fatal("failed progress approval committed marker", err, pending)
				}
				return
			}
			probe := &subjectSelectionProbe{}
			_, err := f.journal.PurgeSubjectHistory(ctx, f.red.codec, pending, HistoryBudget{Rows: 1, Bytes: 1 << 20}, CancellationBudget{Rows: 1, TimeLimit: 5 * time.Second}, allowActivityMaintenance, probe.factory)
			if !errors.Is(err, ErrJournalConflict) {
				t.Fatal("audit drift escaped physical progress reconciliation", phase, err)
			}
			got, err := f.journal.ReadSubjectProgress(ctx, pending, allowActivityMaintenance)
			if err != nil || got != (SubjectHistoryProgress{}) {
				t.Fatal("audit drift did not roll back durable progress", err)
			}
			if phase == "purge" && subjectPurgeCounts(t, f) != [2]int64{3, 3} {
				t.Fatal("audit drift committed physical deletion")
			}
			if f.active(t, f.red.scope.TenantID) != 0 {
				t.Fatal("failed physical workflow did not join source")
			}
		})
	}
}
