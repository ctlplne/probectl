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
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrJournalLease = errors.New("flow conversation: worker lease is unavailable or changed")

// Worker is one private process instance, not a caller-selected worker name.
// It claims metadata only; the engine must independently reload the encrypted
// original credential and complete source authority before doing any work.
type Worker struct {
	journal *Journal
	id      string
	lease   time.Duration
}

func NewWorker(journal *Journal, lease time.Duration) (*Worker, error) {
	if lease < time.Microsecond {
		return nil, ErrMessageBudget
	}
	if err := journal.available(); err != nil {
		return nil, err
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		return nil, ErrJournalUnavailable
	}
	return &Worker{journal: journal, id: id, lease: lease.Truncate(time.Microsecond)}, nil
}

// WorkLease is an operation-local fence, never a bearer/wire capability or
// source permission. Renewal returns a new value; previous values are stale.
type WorkLease struct{ value *workLease }
type workLease struct {
	identity                 historyIdentity
	scope                    MessageScope
	job, worker              string
	generation, cancellation uint64
	until                    time.Time
	proposal                 *Revision
}

func (WorkLease) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*WorkLease) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (WorkLease) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.WorkLease[private]")
}
func (lease WorkLease) Scope() MessageScope {
	if lease.value == nil {
		return MessageScope{}
	}
	return lease.value.scope
}
func (lease WorkLease) Until() time.Time {
	if lease.value == nil {
		return time.Time{}
	}
	return lease.value.until
}

// Proposal is recovery metadata, never confirmation or execution authority.
func (lease WorkLease) Proposal() *Revision {
	if lease.value == nil || lease.value.proposal == nil {
		return nil
	}
	result := *lease.value.proposal
	return &result
}

func validWorkInput(conversation string, input Revision) bool {
	return historyID(conversation) && historyID(input.MessageID) && input.Revision > 0 && input.Revision <= math.MaxInt64
}

// workerMutation holds only short database locks. Authentication callbacks,
// source crypto, native queries and model calls must run outside these locks.
func (j *Journal) workerMutation(ctx context.Context, id historyIdentity, fn func(context.Context, tenancy.Scope, uint64) error) error {
	if err := j.available(); err != nil {
		return err
	}
	err := j.fence.WithTenantWrites(ctx, []string{id.tenant}, func(ctx context.Context) error {
		return j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
			owner, origin, err := bindRequestOwner(ctx, sc)
			if err != nil || sc.Tenant.String() != id.tenant || owner != id.owner || !sameRequestOrigin(origin, id.origin) {
				return ErrMessageDenied
			}
			if err := audit.LockTenantStream(ctx, sc.Q, id.tenant); err != nil {
				return err
			}
			var epoch uint64
			if err := sc.Q.QueryRow(ctx, `SELECT generation FROM flow_conversation_epochs WHERE tenant_id=$1::uuid FOR UPDATE`, id.tenant).Scan(&epoch); err != nil {
				return err
			}
			if epoch == 0 || epoch > math.MaxInt64 {
				return ErrMessageIntegrity
			}
			return fn(ctx, sc, epoch)
		})
	})
	return journalError(ctx, err)
}

// ClaimInput selects exactly one owner-private input; no tenant-wide dispatch
// or source read is implied. PostgreSQL's clock controls expiry and takeover.
// The current context must be genuinely authenticated, never built from a job.
func (w *Worker) ClaimInput(ctx context.Context, conversation string, input Revision, authorize AuthorizeHistory) (WorkLease, error) {
	id, err := historyIdentityFor(ctx)
	if err != nil {
		return WorkLease{}, err
	}
	if !validWorkInput(conversation, input) {
		return WorkLease{}, ErrJournalConflict
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return WorkLease{}, err
	}
	if w == nil || w.journal == nil || !historyID(w.id) || w.lease < time.Microsecond {
		return WorkLease{}, ErrJournalUnavailable
	}
	var result WorkLease
	err = w.journal.workerMutation(ctx, id, func(ctx context.Context, sc tenancy.Scope, epoch uint64) error {
		var job string
		err := sc.Q.QueryRow(ctx, `SELECT j.job_id FROM flow_conversation_jobs j
          JOIN flow_conversation_messages m ON (m.tenant_id,m.owner_id,m.conversation_id,m.message_id,m.revision)=(j.tenant_id,j.owner_id,j.conversation_id,j.input_message_id,j.input_revision)
          WHERE j.tenant_id=$1::uuid AND j.owner_id=$2::uuid AND j.conversation_id=$3::uuid AND j.input_message_id=$4::uuid AND j.input_revision=$5
            AND j.epoch=$6 AND m.epoch=$6 AND m.kind='input' AND (m.expires_at IS NULL OR m.expires_at>clock_timestamp())
            AND (j.status='queued' OR (j.status='processing' AND j.lease_until<=clock_timestamp()))
            AND j.lease_generation<$7 FOR UPDATE OF j SKIP LOCKED`, id.tenant, id.owner, conversation, input.MessageID, int64(input.Revision), int64(epoch), int64(math.MaxInt64)).Scan(&job)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrJournalLease
		}
		if err != nil {
			return err
		}
		claim := &workLease{identity: id, scope: MessageScope{TenantID: id.tenant, OwnerID: id.owner, ConversationID: conversation, MessageID: input.MessageID, Revision: input.Revision, Epoch: epoch}, job: job, worker: w.id}
		var proposalID *string
		var proposalRevision *int64
		err = sc.Q.QueryRow(ctx, `WITH now AS MATERIALIZED (SELECT clock_timestamp() AS at)
          UPDATE flow_conversation_jobs j SET status='processing',worker_id=$4::uuid,lease_generation=j.lease_generation+1,
            lease_until=LEAST(now.at+$5::bigint*interval '1 microsecond',m.expires_at)
          FROM flow_conversation_messages m,now
          WHERE j.tenant_id=$1::uuid AND j.owner_id=$2::uuid AND j.job_id=$3::uuid
            AND (m.tenant_id,m.owner_id,m.conversation_id,m.message_id,m.revision)=(j.tenant_id,j.owner_id,j.conversation_id,j.input_message_id,j.input_revision)
            AND (m.expires_at IS NULL OR m.expires_at>now.at)
          RETURNING j.lease_generation,j.cancel_revision,j.lease_until,j.proposal_message_id,j.proposal_revision`, id.tenant, id.owner, job, w.id, w.lease.Microseconds()).Scan(&claim.generation, &claim.cancellation, &claim.until, &proposalID, &proposalRevision)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrJournalLease
		}
		if err != nil {
			return err
		}
		if (proposalID == nil) != (proposalRevision == nil) {
			return ErrMessageIntegrity
		}
		if proposalID != nil {
			if !historyID(*proposalID) || *proposalRevision <= 0 {
				return ErrMessageIntegrity
			}
			claim.proposal = &Revision{MessageID: *proposalID, Revision: uint64(*proposalRevision)}
		}
		if err := w.journal.recordLease(ctx, sc, claim, "flow.conversation.claim"); err != nil {
			return err
		}
		result = WorkLease{claim}
		return nil
	})
	if err != nil {
		return WorkLease{}, err
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return WorkLease{}, err
	}
	return result, nil
}

func (w *Worker) leaseIdentity(ctx context.Context, lease WorkLease, authorize AuthorizeHistory) (historyIdentity, error) {
	id, err := historyIdentityFor(ctx)
	if err != nil {
		return historyIdentity{}, err
	}
	value := lease.value
	if value == nil || w == nil || value.worker != w.id || value.identity.tenant != id.tenant || value.identity.owner != id.owner || !sameRequestOrigin(value.identity.origin, id.origin) {
		return historyIdentity{}, ErrMessageDenied
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return historyIdentity{}, err
	}
	return id, nil
}

// A shared exact predicate keeps check/renew fenced on the immutable input,
// current epoch, worker instance, takeover/cancel revisions and previous lease.
// Every sensitive operation still needs current original-source authorization.
const liveLeasePredicate = `j.tenant_id=$1::uuid AND j.owner_id=$2::uuid AND j.job_id=$3::uuid
    AND j.worker_id=$4::uuid AND j.lease_generation=$5 AND j.cancel_revision=$6
    AND j.epoch=$7 AND j.conversation_id=$8::uuid AND j.input_message_id=$9::uuid AND j.input_revision=$10
    AND j.status='processing' AND j.lease_until=$11::timestamptz AND j.lease_until>clock_timestamp()
    AND (m.tenant_id,m.owner_id,m.conversation_id,m.message_id,m.revision)=(j.tenant_id,j.owner_id,j.conversation_id,j.input_message_id,j.input_revision)
    AND m.kind='input' AND m.epoch=j.epoch AND (m.expires_at IS NULL OR m.expires_at>clock_timestamp())`

func leaseArguments(value *workLease) []any {
	return []any{value.identity.tenant, value.identity.owner, value.job, value.worker, int64(value.generation), int64(value.cancellation), int64(value.scope.Epoch), value.scope.ConversationID, value.scope.MessageID, int64(value.scope.Revision), value.until}
}

// CheckLease is a fresh database read, not a grant for a later publication.
func (w *Worker) CheckLease(ctx context.Context, lease WorkLease, authorize AuthorizeHistory) error {
	id, err := w.leaseIdentity(ctx, lease, authorize)
	if err != nil {
		return err
	}
	err = w.journal.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		if _, _, err := bindRequestOwner(ctx, sc); err != nil {
			return err
		}
		var live bool
		err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_conversation_jobs j,flow_conversation_messages m,flow_conversation_epochs e WHERE `+liveLeasePredicate+`
          AND e.tenant_id=j.tenant_id AND e.generation=j.epoch)`, leaseArguments(lease.value)...).Scan(&live)
		if err == nil && !live {
			return ErrJournalLease
		}
		return err
	})
	if err != nil {
		return journalError(ctx, err)
	}
	return id.authorize(ctx, authorize)
}

// Renew never resurrects an expired or replaced lease and cannot extend past
// the input's immutable privacy deadline. Old WorkLease values become stale.
func (w *Worker) Renew(ctx context.Context, lease WorkLease, authorize AuthorizeHistory) (WorkLease, error) {
	id, err := w.leaseIdentity(ctx, lease, authorize)
	if err != nil {
		return WorkLease{}, err
	}
	value := lease.value
	var result WorkLease
	err = w.journal.workerMutation(ctx, id, func(ctx context.Context, sc tenancy.Scope, epoch uint64) error {
		if epoch != value.scope.Epoch {
			return ErrJournalGeneration
		}
		args := append(leaseArguments(value), w.lease.Microseconds())
		renewed := *value
		err := sc.Q.QueryRow(ctx, `UPDATE flow_conversation_jobs j
		  SET lease_until=LEAST(clock_timestamp()+$12::bigint*interval '1 microsecond',m.expires_at),lease_generation=j.lease_generation+1
          FROM flow_conversation_messages m WHERE `+liveLeasePredicate+`
		  AND j.lease_generation<9223372036854775807
		  RETURNING j.lease_until,j.lease_generation`, args...).Scan(&renewed.until, &renewed.generation)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrJournalLease
		}
		if err != nil {
			return err
		}
		// Generation changes even at a capped immutable deadline, so every
		// earlier lease value is stale regardless of timestamp precision.
		if err := w.journal.recordLease(ctx, sc, &renewed, "flow.conversation.renew"); err != nil {
			return err
		}
		result = WorkLease{&renewed}
		return nil
	})
	if err != nil {
		return WorkLease{}, err
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return WorkLease{}, err
	}
	return result, nil
}

// CancelInput is explicit current-owner cancellation, including old-origin
// work. It has no rerun/confirm/resume transition and returns no source text.
func (j *Journal) CancelInput(ctx context.Context, conversation string, input Revision, authorize AuthorizeHistory) error {
	id, err := historyIdentityFor(ctx)
	if err != nil {
		return err
	}
	if !validWorkInput(conversation, input) {
		return ErrJournalConflict
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return err
	}
	return j.workerMutation(ctx, id, func(ctx context.Context, sc tenancy.Scope, _ uint64) error {
		var job string
		var revision uint64
		err := sc.Q.QueryRow(ctx, `UPDATE flow_conversation_jobs SET status='canceled',worker_id=NULL,lease_until=NULL,cancel_revision=cancel_revision+1
          WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid AND input_message_id=$4::uuid AND input_revision=$5
            AND status IN ('queued','processing') AND cancel_revision<$6 RETURNING job_id,cancel_revision`, id.tenant, id.owner, conversation, input.MessageID, int64(input.Revision), int64(math.MaxInt64)).Scan(&job, &revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrJournalLease
		}
		if err != nil {
			return err
		}
		return j.record(ctx, sc, id.owner, "flow.conversation.cancel", input.MessageID, map[string]any{
			"conversation_id": conversation, "message_revision": input.Revision, "job_id": job, "cancel_revision": revision,
		})
	})
}

func (j *Journal) recordLease(ctx context.Context, sc tenancy.Scope, value *workLease, action string) error {
	return j.record(ctx, sc, value.identity.owner, action, value.scope.MessageID, map[string]any{
		"conversation_id": value.scope.ConversationID, "message_revision": value.scope.Revision, "job_id": value.job,
		"generation": value.scope.Epoch, "lease_generation": value.generation, "cancel_revision": value.cancellation,
	})
}
