// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"fmt"
	"io"
	"math"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// SubjectHistoryProgress is durable physical progress for one exact pending
// plan. SourceEmpty proves complete matching found no remaining selected leaf;
// it never proves all-plane erasure or confers intent-clear/source authority.
type SubjectHistoryProgress struct {
	MessagesDeleted, JobsDeleted int64
	SourceEmpty                  bool
}

func (SubjectHistoryProgress) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*SubjectHistoryProgress) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (SubjectHistoryProgress) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "flowconversation.SubjectHistoryProgress[private]")
}

func advanceSubjectProgress(previous SubjectHistoryProgress, messages, jobs int64) (SubjectHistoryProgress, error) {
	if previous.MessagesDeleted < 0 || previous.JobsDeleted < 0 || messages < 0 || jobs < 0 || previous.SourceEmpty || messages > math.MaxInt64-previous.MessagesDeleted || jobs > math.MaxInt64-previous.JobsDeleted {
		return SubjectHistoryProgress{}, ErrJournalConflict
	}
	return SubjectHistoryProgress{MessagesDeleted: previous.MessagesDeleted + messages, JobsDeleted: previous.JobsDeleted + jobs}, nil
}

func readSubjectProgressTx(ctx context.Context, sc tenancy.Scope, pending Invalidation) (SubjectHistoryProgress, error) {
	v := pending.value
	if v == nil || v.tenant != sc.Tenant.String() || v.request.Kind != MaintenanceSubjectErase || !validMaintenanceRequest(v.request) || v.generation == 0 || v.generation > math.MaxInt64 {
		return SubjectHistoryProgress{}, ErrMessageDenied
	}
	var result SubjectHistoryProgress
	err := sc.Q.QueryRow(ctx, `SELECT operation_messages_deleted,operation_jobs_deleted,operation_source_empty FROM flow_conversation_epochs WHERE tenant_id=$1::uuid AND operation_id=$2::uuid AND operation_kind='subject_erase' AND operation_binding=$3 AND generation=$4 AND invalidating AND operation_plan IS NOT NULL AND length(operation_plan)>0`, v.tenant, v.request.ID, v.request.Binding[:], int64(v.generation)).Scan(&result.MessagesDeleted, &result.JobsDeleted, &result.SourceEmpty)
	if err != nil {
		return SubjectHistoryProgress{}, err
	}
	if result.MessagesDeleted < 0 || result.JobsDeleted < 0 {
		return SubjectHistoryProgress{}, ErrMessageIntegrity
	}
	return result, nil
}

func writeSubjectProgressTx(ctx context.Context, sc tenancy.Scope, pending Invalidation, previous, next SubjectHistoryProgress) error {
	v := pending.value
	if v == nil || v.tenant != sc.Tenant.String() || next.MessagesDeleted < previous.MessagesDeleted || next.JobsDeleted < previous.JobsDeleted || previous.SourceEmpty && next != previous {
		return ErrJournalConflict
	}
	tag, err := sc.Q.Exec(ctx, `UPDATE flow_conversation_epochs SET operation_messages_deleted=$5,operation_jobs_deleted=$6,operation_source_empty=$7 WHERE tenant_id=$1::uuid AND operation_id=$2::uuid AND operation_kind='subject_erase' AND operation_binding=$3 AND generation=$4 AND invalidating AND operation_messages_deleted=$8 AND operation_jobs_deleted=$9 AND operation_source_empty=$10`, v.tenant, v.request.ID, v.request.Binding[:], int64(v.generation), next.MessagesDeleted, next.JobsDeleted, next.SourceEmpty, previous.MessagesDeleted, previous.JobsDeleted, previous.SourceEmpty)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrJournalConflict
	}
	return nil
}

// ReadSubjectProgress reloads exact durable counts. A caller must not add a
// returned batch twice or infer progress from a missing leaf after uncertainty.
func (j *Journal) ReadSubjectProgress(ctx context.Context, pending Invalidation, authorize AuthorizeMaintenance) (SubjectHistoryProgress, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil || pending.value == nil || pending.value.tenant != tenant {
		return SubjectHistoryProgress{}, messageError(ctx, ErrMessageDenied)
	}
	if err := authorizeMaintenance(ctx, tenant, authorize); err != nil {
		return SubjectHistoryProgress{}, err
	}
	var result SubjectHistoryProgress
	err = j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = readSubjectProgressTx(ctx, sc, pending)
		return err
	})
	if err == nil {
		err = authorizeMaintenance(ctx, tenant, authorize)
	}
	if err != nil {
		return SubjectHistoryProgress{}, journalError(ctx, err)
	}
	return result, nil
}

func (j *Journal) recordSubjectSourceEmpty(ctx context.Context, selection subjectLeafSelection, authorize AuthorizeMaintenance) error {
	pending := selection.pending
	if !selection.exhausted || len(selection.leaves) != 0 || pending.value == nil {
		return ErrMessageDenied
	}
	return j.WithDrainedInvalidation(ctx, pending, authorize, func(ctx context.Context) error {
		return j.fence.WithTenantWrites(ctx, []string{pending.value.tenant}, func(ctx context.Context) error {
			return j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
				if err := bindLifecycle(ctx, sc); err != nil {
					return err
				}
				if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
					return err
				}
				state, err := readConversationEpoch(ctx, sc, epochUpdate)
				if err != nil {
					return err
				}
				if !state.matches(pending.value.request) || state.generation != pending.value.generation {
					return ErrJournalGeneration
				}
				before, err := countSubjectPurge(ctx, sc) // actual drain + no live jobs
				if err != nil {
					return err
				}
				previous, err := readSubjectProgressTx(ctx, sc, pending)
				if err != nil || previous.SourceEmpty {
					return err
				}
				next := previous
				next.SourceEmpty = true
				if err := writeSubjectProgressTx(ctx, sc, pending, previous, next); err != nil {
					return err
				}
				if err := j.record(ctx, sc, "system:flow-conversation", "flow.conversation.subject_source_empty", pending.value.request.ID, map[string]any{"generation": state.generation, "scanned": selection.scanned, "messages_deleted": next.MessagesDeleted, "jobs_deleted": next.JobsDeleted}); err != nil {
					return err
				}
				verified, err := readSubjectProgressTx(ctx, sc, pending)
				if err != nil {
					return err
				}
				if verified != next {
					return ErrJournalConflict
				}
				after, err := countSubjectPurge(ctx, sc)
				if err != nil {
					return err
				}
				if after != before {
					return ErrJournalConflict
				}
				return nil
			})
		})
	})
}
