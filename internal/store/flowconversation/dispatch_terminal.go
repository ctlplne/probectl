// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"math"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DispatchFailure is a closed metadata category, never a raw exception or a
// generic-error classifier. The service must positively establish a refusal;
// transient key, repository or audit unavailability does not imply origin loss.
type DispatchFailure uint8

const (
	DispatchOriginInvalid DispatchFailure = iota + 1
	DispatchSourceExpired
	DispatchSourceInvalid
	DispatchAuthorityRefused
)

func (reason DispatchFailure) code() string {
	switch reason {
	case DispatchOriginInvalid:
		return "origin_invalid"
	case DispatchSourceExpired:
		return "source_expired"
	case DispatchSourceInvalid:
		return "source_invalid"
	case DispatchAuthorityRefused:
		return "authority_refused"
	default:
		return ""
	}
}

// FailDispatch performs independently authorized source-free terminal cleanup
// after a creator can no longer authorize work. It never reads/decrypts source
// or fabricates that user's Principal. CAS refuses any newly claimed, renewed,
// published, canceled or lifecycle-fenced candidate. Audit failure rolls back.
func (j *Journal) FailDispatch(ctx context.Context, candidate DispatchCandidate, reason DispatchFailure, authorize AuthorizeDispatch) error {
	if candidate.value == nil || reason.code() == "" {
		return messageError(ctx, ErrMessageIntegrity)
	}
	value := *candidate.value
	if err := value.scope.validate(ctx); err != nil {
		return err
	}
	if !historyID(value.job) || value.scope.Revision > math.MaxInt64 || value.scope.Epoch > math.MaxInt64 ||
		value.generation >= math.MaxInt64 || value.cancellation >= math.MaxInt64 || (value.status != "queued" && value.status != "processing") {
		return ErrMessageIntegrity
	}
	id, err := dispatchIdentityFor(ctx, value.scope.OwnerID)
	if err != nil {
		return err
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return err
	}
	if err := j.available(); err != nil {
		return err
	}
	err = j.fence.WithTenantWrites(ctx, []string{id.tenant}, func(ctx context.Context) error {
		return j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
			if sc.Tenant.String() != id.tenant {
				return ErrMessageDenied
			}
			if err := bindOwner(ctx, sc, id.owner); err != nil {
				return err
			}
			if err := audit.LockTenantStream(ctx, sc.Q, id.tenant); err != nil {
				return err
			}
			var epoch uint64
			if err := sc.Q.QueryRow(ctx, `SELECT generation FROM flow_conversation_epochs WHERE tenant_id=$1::uuid FOR UPDATE`, id.tenant).Scan(&epoch); err != nil {
				return err
			}
			if epoch != value.scope.Epoch {
				return ErrJournalGeneration
			}
			changed, err := sc.Q.Exec(ctx, `UPDATE flow_conversation_jobs SET status='failed',worker_id=NULL,lease_until=NULL,
              lease_generation=lease_generation+1,cancel_revision=cancel_revision+1
              WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND job_id=$3::uuid AND conversation_id=$4::uuid
                AND input_message_id=$5::uuid AND input_revision=$6 AND epoch=$7
                AND lease_generation=$8 AND cancel_revision=$9 AND status=$10
                AND (status='queued' OR (status='processing' AND lease_until<=clock_timestamp()))`,
				id.tenant, id.owner, value.job, value.scope.ConversationID, value.scope.MessageID, int64(value.scope.Revision), int64(value.scope.Epoch),
				int64(value.generation), int64(value.cancellation), value.status)
			if err != nil {
				return err
			}
			if changed.RowsAffected() != 1 {
				return ErrJournalLease
			}
			return j.record(ctx, sc, "system:flow-conversation", "flow.conversation.failed", value.scope.MessageID, map[string]any{
				"owner_id": id.owner, "conversation_id": value.scope.ConversationID, "message_revision": value.scope.Revision,
				"job_id": value.job, "generation": value.scope.Epoch, "lease_generation": value.generation + 1,
				"cancel_revision": value.cancellation + 1, "reason": reason.code(),
			})
		})
	})
	if err != nil {
		return journalError(ctx, err)
	}
	return id.authorize(ctx, authorize)
}
