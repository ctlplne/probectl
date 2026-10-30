// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PreparedProposal contains a pair encrypted outside mutation locks. Services
// must validate the typed proposal, complete ancestry and current source/policy
// before preparation and again through authorize before publication. Neither a
// proposal nor this private value grants confirmation or native execution.
type PreparedProposal struct{ value *preparedProposal }
type preparedProposal struct {
	lease    *workLease
	input    StoredMessage
	scope    MessageScope
	meta     InputMetadata
	required []string
	sealed   SealedMessage
}

func (PreparedProposal) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*PreparedProposal) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (PreparedProposal) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.PreparedProposal[private]")
}

// PrepareProposal authenticates the original input header before encrypting a
// proposal. A successor credential cannot prepare old work. The new header must
// preserve every authenticated input dependency, even for a harmless plan.
func (c *Codec) PrepareProposal(ctx context.Context, lease WorkLease, input StoredMessage, scope MessageScope, meta InputMetadata, requirements []string, body []byte, authorize AuthorizeMessage) (PreparedProposal, error) {
	if err := scope.validate(ctx); err != nil {
		return PreparedProposal{}, err
	}
	if err := c.available(); err != nil {
		return PreparedProposal{}, err
	}
	value := lease.value
	if value == nil || input.value == nil || input.Scope() != value.scope || input.Kind() != "input" || value.proposal != nil || authorize == nil {
		return PreparedProposal{}, ErrMessageDenied
	}
	origin, err := requestOrigin(ctx, scope.TenantID, scope.OwnerID)
	if err != nil || !sameRequestOrigin(origin, value.identity.origin) {
		return PreparedProposal{}, messageError(ctx, ErrMessageDenied)
	}
	parent := input.Metadata()
	meta.FrozenAt, meta.ExpiresAt = meta.FrozenAt.UTC(), StorageDeadline(meta.ExpiresAt)
	if scope.TenantID != value.scope.TenantID || scope.OwnerID != value.scope.OwnerID || scope.ConversationID != value.scope.ConversationID || scope.Epoch != value.scope.Epoch || scope.Revision > math.MaxInt64 ||
		!validInputMetadata(scope, meta) || meta.Parent == nil || meta.Parent.MessageID != value.scope.MessageID || meta.Parent.Revision != value.scope.Revision ||
		!meta.FrozenAt.Equal(parent.FrozenAt) || meta.ExpiresAt.IsZero() || !parent.ExpiresAt.IsZero() && meta.ExpiresAt.After(parent.ExpiresAt) {
		return PreparedProposal{}, ErrMessageIntegrity
	}
	parentRef := *meta.Parent
	meta.Parent = &parentRef
	if len(body) > c.budget.PlainBytes {
		return PreparedProposal{}, ErrMessageBudget
	}
	plain := bytes.Clone(body)
	defer clear(plain)
	required, err := canonicalMessageRequirements(requirements, c.budget.HeaderBytes)
	if err != nil {
		return PreparedProposal{}, err
	}
	err = c.CheckHeader(ctx, input.Scope(), input.Ciphertext(), func(ctx context.Context, scope MessageScope, stored auth.WorkerCredentialRef, inherited []string) error {
		if !sameRequestOrigin(stored, origin) {
			return ErrMessageDenied
		}
		for _, permission := range inherited {
			if !slices.Contains(required, permission) {
				return ErrMessageDenied
			}
		}
		return authorize(ctx, scope, stored, slices.Clone(inherited))
	})
	if err != nil {
		return PreparedProposal{}, err
	}
	if err := authorize(ctx, scope, origin, slices.Clone(required)); err != nil {
		return PreparedProposal{}, messageError(ctx, ErrMessageDenied)
	}
	sealed, err := c.Seal(ctx, scope, origin, required, plain)
	if err != nil {
		return PreparedProposal{}, err
	}
	if err := authorize(ctx, scope, origin, slices.Clone(required)); err != nil {
		return PreparedProposal{}, messageError(ctx, ErrMessageDenied)
	}
	if err := ctx.Err(); err != nil {
		return PreparedProposal{}, err
	}
	return PreparedProposal{&preparedProposal{lease: value, input: input, scope: scope, meta: meta, required: required, sealed: sealed}}, nil
}

// PublishProposal atomically appends the proposal, exact job link, fresh lease
// generation and mandatory audit. Processing continues with the returned lease:
// publishing a proposal does not complete a question or authorize execution.
func (w *Worker) PublishProposal(ctx context.Context, lease WorkLease, prepared PreparedProposal, authorize AuthorizeMessage) (WorkLease, error) {
	p := prepared.value
	if p == nil || lease.value == nil || p.lease != lease.value || p.sealed.parts == nil || authorize == nil {
		return WorkLease{}, ErrMessageDenied
	}
	id, err := w.leaseIdentity(ctx, lease, func(ctx context.Context, _, _ string, origin auth.WorkerCredentialRef) error {
		return authorize(ctx, p.scope, origin, slices.Clone(p.required))
	})
	if err != nil {
		return WorkLease{}, err
	}
	var result WorkLease
	err = w.journal.workerMutation(ctx, id, func(ctx context.Context, sc tenancy.Scope, epoch uint64) error {
		if epoch != p.scope.Epoch {
			return ErrJournalGeneration
		}
		args := append(leaseArguments(lease.value), p.input.value.sealed.parts.header, p.input.value.sealed.parts.payload, p.meta.FrozenAt.Format(time.RFC3339Nano), p.meta.ExpiresAt)
		// Hold the exact input through the short mutation, including paired key
		// rotation. Correct maintenance also shares the outer writer/epoch fence.
		const original = ` AND j.proposal_message_id IS NULL AND j.lease_generation<9223372036854775807
            AND m.private_header=$12 AND m.private_payload=$13 AND m.frozen_at=$14
            AND $15::timestamptz>clock_timestamp() AND (m.expires_at IS NULL OR $15::timestamptz<=m.expires_at)`
		var job string
		err := sc.Q.QueryRow(ctx, `SELECT j.job_id FROM flow_conversation_jobs j,flow_conversation_messages m WHERE `+liveLeasePredicate+original+` FOR UPDATE OF j FOR SHARE OF m`, args...).Scan(&job)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrJournalLease
		}
		if err != nil {
			return err
		}
		tag, err := sc.Q.Exec(ctx, `INSERT INTO flow_conversation_messages(tenant_id,owner_id,conversation_id,message_id,revision,epoch,parent_message_id,parent_revision,kind,frozen_at,expires_at,private_header,private_payload,position)
            SELECT $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7::uuid,$8,'proposal',$9,$10::timestamptz,$11,$12,
              COALESCE((SELECT max(position) FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid),0)+1
            WHERE $10::timestamptz>clock_timestamp()`, p.scope.TenantID, p.scope.OwnerID, p.scope.ConversationID, p.scope.MessageID, int64(p.scope.Revision), int64(p.scope.Epoch), p.meta.Parent.MessageID, int64(p.meta.Parent.Revision), p.meta.FrozenAt.Format(time.RFC3339Nano), p.meta.ExpiresAt, p.sealed.parts.header, p.sealed.parts.payload)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrJournalConflict
		}
		renewed := *lease.value
		renewed.proposal = &Revision{MessageID: p.scope.MessageID, Revision: p.scope.Revision}
		args = append(args, p.scope.MessageID, int64(p.scope.Revision))
		err = sc.Q.QueryRow(ctx, `UPDATE flow_conversation_jobs j SET proposal_message_id=$16::uuid,proposal_revision=$17,lease_generation=j.lease_generation+1
            FROM flow_conversation_messages m WHERE `+liveLeasePredicate+original+` RETURNING j.lease_generation`, args...).Scan(&renewed.generation)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrJournalLease
		}
		if err != nil {
			return err
		}
		if err := w.journal.record(ctx, sc, id.owner, "flow.conversation.proposal", p.scope.MessageID, map[string]any{
			"conversation_id": p.scope.ConversationID, "message_revision": p.scope.Revision, "input_message_id": p.meta.Parent.MessageID,
			"input_revision": p.meta.Parent.Revision, "job_id": job, "generation": epoch, "lease_generation": renewed.generation,
		}); err != nil {
			return err
		}
		result = WorkLease{&renewed}
		return nil
	})
	if err != nil {
		return WorkLease{}, err
	}
	if err := authorize(ctx, p.scope, id.origin, slices.Clone(p.required)); err != nil {
		return WorkLease{}, messageError(ctx, ErrMessageDenied)
	}
	return result, nil
}
