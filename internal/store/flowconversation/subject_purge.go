// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Counts describe one physical transaction and whole-family remaining rows,
// never complete subject/native/all-plane erasure or intent-clear authority.
type subjectPurgeBatch struct {
	messagesDeleted, jobsDeleted     int64
	messagesRemaining, jobsRemaining int64
	referencesRemaining              int64
}

func (subjectPurgeBatch) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*subjectPurgeBatch) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (subjectPurgeBatch) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.subjectPurgeBatch[private]")
}

// purgeSubjectLeaf removes at most budget.Rows referencing jobs and one exact
// selected leaf. Actual matching has already drained. A changed/missing pair,
// child or intent requires a new complete source pass; uncertainty is never an
// assumed successful replay. No decryption or creator credential is needed.
func (j *Journal) purgeSubjectLeaf(ctx context.Context, selection subjectLeafSelection, index int, budget CancellationBudget, authorize AuthorizeMaintenance) (subjectPurgeBatch, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return subjectPurgeBatch{}, err
	}
	if budget.Rows <= 0 || budget.TimeLimit <= 0 {
		return subjectPurgeBatch{}, ErrMessageBudget
	}
	pending := selection.pending
	if pending.value == nil || pending.value.tenant != tenant || pending.value.request.Kind != MaintenanceSubjectErase || !validMaintenanceRequest(pending.value.request) || pending.value.generation == 0 || pending.value.generation > math.MaxInt64 || index < 0 || index >= len(selection.leaves) {
		return subjectPurgeBatch{}, ErrMessageDenied
	}
	stored := selection.leaves[index]
	if err := validSubjectPurgeLeaf(ctx, stored); err != nil {
		return subjectPurgeBatch{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.TimeLimit)
	defer cancel()
	var result subjectPurgeBatch
	err = j.WithDrainedInvalidation(ctx, pending, authorize, func(ctx context.Context) error {
		return j.fence.WithTenantWrites(ctx, []string{tenant}, func(ctx context.Context) error {
			return j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
				if sc.Tenant.String() != tenant {
					return ErrMessageDenied
				}
				if err := bindLifecycle(ctx, sc); err != nil {
					return err
				}
				if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
					return err
				}
				state, err := readConversationEpoch(ctx, sc, epochUpdate)
				if err != nil {
					return err
				}
				if !state.matches(pending.value.request) || state.generation != pending.value.generation {
					return ErrJournalGeneration
				}
				// Registration takes this same epoch lock. Recheck actual drain
				// here even if the longer outer SQL family lease was lost.
				before, err := countSubjectPurge(ctx, sc)
				if err != nil {
					return err
				}
				if err := lockSubjectPurgeLeaf(ctx, sc, stored); err != nil {
					return err
				}
				refs, err := countSubjectJobReferences(ctx, sc, stored)
				if err != nil {
					return err
				}
				if refs > 0 {
					args := append(subjectJobArguments(stored), int64(budget.Rows))
					tag, err := sc.Q.Exec(ctx, `WITH candidates AS (SELECT job_id FROM flow_conversation_jobs WHERE `+subjectJobPredicate+`
 ORDER BY job_id LIMIT $6 FOR UPDATE SKIP LOCKED)
 DELETE FROM flow_conversation_jobs j USING candidates c WHERE j.tenant_id=$1::uuid AND j.owner_id=$2::uuid AND j.conversation_id=$3::uuid AND j.job_id=c.job_id`, args...)
					if err != nil {
						return err
					}
					result.jobsDeleted = tag.RowsAffected()
				}
				result.referencesRemaining, err = countSubjectJobReferences(ctx, sc, stored)
				if err != nil {
					return err
				}
				if result.jobsDeleted > int64(budget.Rows) || !exactPurgeDelta(refs, result.jobsDeleted, result.referencesRemaining) {
					return ErrJournalConflict
				}
				if result.referencesRemaining == 0 {
					// The row lock also blocks new FK references. These explicit
					// predicates still refuse any child/job introduced in this
					// transaction; never rely on an unbounded FK cascade.
					tag, err := sc.Q.Exec(ctx, `DELETE FROM flow_conversation_messages WHERE `+subjectExactLeafPredicate+`
 AND `+subjectLeafPredicate+` AND NOT EXISTS(SELECT 1 FROM flow_conversation_jobs WHERE `+subjectJobPredicate+`)`, subjectLeafArguments(stored)...)
					if err != nil {
						return err
					}
					result.messagesDeleted = tag.RowsAffected()
					if result.messagesDeleted != 1 {
						return ErrJournalConflict
					}
				}
				after, err := countSubjectPurge(ctx, sc)
				if err != nil {
					return err
				}
				if !exactPurgeDelta(before.messagesRemaining, result.messagesDeleted, after.messagesRemaining) || !exactPurgeDelta(before.jobsRemaining, result.jobsDeleted, after.jobsRemaining) {
					return ErrJournalConflict
				}
				result.messagesRemaining, result.jobsRemaining = after.messagesRemaining, after.jobsRemaining
				if result.messagesDeleted == 0 && result.jobsDeleted == 0 {
					return ErrJournalUnavailable
				}
				if err := j.record(ctx, sc, "system:flow-conversation", "flow.conversation.subject_purge", pending.value.request.ID, map[string]any{
					"generation": state.generation, "owner_id": stored.Scope().OwnerID, "conversation_id": stored.Scope().ConversationID,
					"message_id": stored.Scope().MessageID, "revision": stored.Scope().Revision,
					"messages_deleted": result.messagesDeleted, "jobs_deleted": result.jobsDeleted,
					"messages_remaining": result.messagesRemaining, "jobs_remaining": result.jobsRemaining, "references_remaining": result.referencesRemaining,
				}); err != nil {
					return err
				}
				// A mandatory audit appender is part of this same transaction;
				// its failure or unexpected mutation cannot escape reconciliation.
				verified, err := countSubjectPurge(ctx, sc)
				if err != nil {
					return err
				}
				if verified != after {
					return ErrJournalConflict
				}
				return nil
			})
		})
	})
	if err != nil {
		return subjectPurgeBatch{}, journalError(ctx, err)
	}
	return result, nil
}

func validSubjectPurgeLeaf(ctx context.Context, stored StoredMessage) error {
	v := stored.value
	// Only the private complete selector constructs these work items, after
	// authenticating both envelopes. Their original bytes remain CAS inputs.
	// HasScheme tests a live opener registration, so it cannot guard this
	// source-free step after the selected source has actually drained.
	if v == nil || v.scope.validate(ctx) != nil || v.scope.Epoch > math.MaxInt64 || v.scope.Revision > math.MaxInt64 || v.position == 0 || v.position > math.MaxInt64 || !validInputMetadata(v.scope, v.meta) || !historyKind(v.kind) || v.sealed.parts == nil || v.sealed.parts.header == "" || v.sealed.parts.payload == "" {
		return messageError(ctx, ErrMessageIntegrity)
	}
	return nil
}

const subjectExactLeafPredicate = `tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid AND message_id=$4::uuid AND revision=$5
 AND epoch=$6 AND kind=$7 AND frozen_at=$8 AND expires_at IS NOT DISTINCT FROM $9::timestamptz
 AND parent_message_id IS NOT DISTINCT FROM $10::uuid AND parent_revision IS NOT DISTINCT FROM $11::bigint
 AND position=$12 AND private_header=$13 AND private_payload=$14`

const subjectJobPredicate = `tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid
 AND ((input_message_id=$4::uuid AND input_revision=$5) OR (proposal_message_id=$4::uuid AND proposal_revision=$5))`

const subjectLeafPredicate = `NOT EXISTS(SELECT 1 FROM flow_conversation_messages child
 WHERE child.tenant_id=$1::uuid AND child.owner_id=$2::uuid AND child.conversation_id=$3::uuid AND child.parent_message_id=$4::uuid AND child.parent_revision=$5)`

func subjectJobArguments(stored StoredMessage) []any {
	s := stored.value.scope
	return []any{s.TenantID, s.OwnerID, s.ConversationID, s.MessageID, int64(s.Revision)}
}

func subjectLeafArguments(stored StoredMessage) []any {
	v := stored.value
	var expires, parent, revision any
	if !v.meta.ExpiresAt.IsZero() {
		expires = v.meta.ExpiresAt
	}
	if v.meta.Parent != nil {
		parent, revision = v.meta.Parent.MessageID, int64(v.meta.Parent.Revision)
	}
	return append(subjectJobArguments(stored), int64(v.scope.Epoch), v.kind, v.meta.FrozenAt.UTC().Format(time.RFC3339Nano), expires, parent, revision, int64(v.position), v.sealed.parts.header, v.sealed.parts.payload)
}

func lockSubjectPurgeLeaf(ctx context.Context, sc tenancy.Scope, stored StoredMessage) error {
	var leaf bool
	err := sc.Q.QueryRow(ctx, `SELECT `+subjectLeafPredicate+` FROM flow_conversation_messages WHERE `+subjectExactLeafPredicate+` FOR UPDATE`, subjectLeafArguments(stored)...).Scan(&leaf)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !leaf {
		return ErrJournalConflict
	}
	return err
}

func countSubjectJobReferences(ctx context.Context, sc tenancy.Scope, stored StoredMessage) (int64, error) {
	var count int64
	err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_jobs WHERE `+subjectJobPredicate, subjectJobArguments(stored)...).Scan(&count)
	return count, err
}

func countSubjectPurge(ctx context.Context, sc tenancy.Scope) (subjectPurgeBatch, error) {
	var result subjectPurgeBatch
	var jobs, operations int64
	err := sc.Q.QueryRow(ctx, `SELECT (SELECT count(*) FROM flow_conversation_messages WHERE tenant_id=$1::uuid),
 (SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid),
 (SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND status IN ('queued','processing')),
 (SELECT count(*) FROM flow_conversation_activity WHERE tenant_id=$1::uuid AND drained_at IS NULL)`, sc.Tenant.String()).Scan(&result.messagesRemaining, &result.jobsRemaining, &jobs, &operations)
	if err != nil {
		return subjectPurgeBatch{}, err
	}
	if operations != 0 {
		return subjectPurgeBatch{}, ErrJournalDraining
	}
	if jobs != 0 {
		return subjectPurgeBatch{}, ErrJournalConflict
	}
	return result, nil
}
