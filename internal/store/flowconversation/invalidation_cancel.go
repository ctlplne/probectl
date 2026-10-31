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
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type CancellationBudget struct {
	Rows      int
	TimeLimit time.Duration
}

// CancellationBatch counts active job metadata only, not remaining source,
// results, keys or positive drain acknowledgements. Zero is not an erasure proof.
type CancellationBatch struct{ Canceled, ActiveRemaining int64 }

func (CancellationBatch) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (CancellationBatch) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "flowconversation.CancellationBatch[private]")
}

type invalidatedJob struct {
	owner, job               string
	generation, cancellation uint64
}

// CancelInvalidated cancels a bounded batch under the exact pending plan. New
// attempts have already been fenced by BeginInvalidation. This source-free
// metadata sweep grants no decryption/creator credentials and clears no intent.
// Full-tenant callers run it before ordinary writer/audit offboarding fences;
// later destructive phases need separately audited lifecycle authority.
func (j *Journal) CancelInvalidated(ctx context.Context, pending Invalidation, budget CancellationBudget, authorize AuthorizeMaintenance) (CancellationBatch, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return CancellationBatch{}, err
	}
	if pending.value == nil || pending.value.tenant != tenant {
		return CancellationBatch{}, ErrMessageDenied
	}
	if budget.Rows <= 0 || budget.TimeLimit <= 0 {
		return CancellationBatch{}, ErrMessageBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget.TimeLimit)
	defer cancel()
	var result CancellationBatch
	err = j.WithInvalidationLease(ctx, pending, authorize, func(ctx context.Context) error {
		return j.fence.WithTenantWrites(ctx, []string{tenant}, func(ctx context.Context) error {
			return j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
				if sc.Tenant.String() != tenant {
					return ErrMessageDenied
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
				if err := bindLifecycle(ctx, sc); err != nil {
					return err
				}
				jobs, err := selectInvalidatedJobs(ctx, sc, budget.Rows)
				if err != nil {
					return err
				}
				for _, job := range jobs {
					changed, err := sc.Q.Exec(ctx, `UPDATE flow_conversation_jobs SET status='canceled',worker_id=NULL,lease_until=NULL,lease_generation=lease_generation+1,cancel_revision=cancel_revision+1 WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND job_id=$3::uuid AND lease_generation=$4 AND cancel_revision=$5 AND status IN ('queued','processing')`, tenant, job.owner, job.job, int64(job.generation), int64(job.cancellation))
					if err != nil {
						return err
					}
					if changed.RowsAffected() != 1 {
						return ErrJournalConflict
					}
					result.Canceled++
				}
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND status IN ('queued','processing')`, tenant).Scan(&result.ActiveRemaining); err != nil {
					return err
				}
				if result.Canceled == 0 {
					return nil
				}
				return j.record(ctx, sc, "system:flow-conversation", "flow.conversation.cancel_invalidated", pending.value.request.ID, map[string]any{"purpose": string(pending.value.request.Kind), "generation": state.generation, "canceled_jobs": result.Canceled, "active_remaining": result.ActiveRemaining})
			})
		})
	})
	if err != nil {
		return CancellationBatch{}, journalError(ctx, err)
	}
	return result, nil
}

func selectInvalidatedJobs(ctx context.Context, sc tenancy.Scope, limit int) ([]invalidatedJob, error) {
	rows, err := sc.Q.Query(ctx, `SELECT owner_id::text,job_id::text,lease_generation,cancel_revision FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND status IN ('queued','processing') ORDER BY owner_id,job_id LIMIT $2 FOR UPDATE SKIP LOCKED`, sc.Tenant.String(), int64(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []invalidatedJob
	for rows.Next() {
		var job invalidatedJob
		if err := rows.Scan(&job.owner, &job.job, &job.generation, &job.cancellation); err != nil {
			return nil, err
		}
		if !historyID(job.owner) || !historyID(job.job) || job.generation >= math.MaxInt64 || job.cancellation >= math.MaxInt64 {
			return nil, ErrJournalGeneration
		}
		result = append(result, job)
	}
	return result, rows.Err()
}
