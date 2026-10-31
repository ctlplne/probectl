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

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// AuthorizeDispatch is independent internal operational authority, never a
// request/provider telemetry grant. It must check current tenant lifecycle and
// the scheduler's permission to inspect this exact owner's source-free work.
// It grants no permission to decrypt source, impersonate an owner or execute.
type AuthorizeDispatch func(context.Context, string, string) error

// DispatchBudget bounds one metadata page, not the backlog or retained turns.
// Encrypted header bytes and SQL/authorization time are separate resources.
type DispatchBudget struct {
	Rows, HeaderBytes int
	TimeLimit         time.Duration
}

// DispatchCandidate contains no source payload and is never a wire capability.
// Even its authenticated header is only a bootstrap for current authorization.
type DispatchCandidate struct{ value *dispatchCandidate }
type dispatchCandidate struct {
	scope                    MessageScope
	job, status              string
	generation, cancellation uint64
	header                   string
}

func (DispatchCandidate) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*DispatchCandidate) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (DispatchCandidate) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.DispatchCandidate[private]")
}
func (candidate DispatchCandidate) Scope() MessageScope {
	if candidate.value == nil {
		return MessageScope{}
	}
	return candidate.value.scope
}

// DispatchCursor is operation-local keyset metadata. A sweep is best-effort:
// concurrent insert/eligibility changes are revisited by the next fresh sweep.
// It is not an immutable history snapshot, public cursor or execution grant.
type DispatchCursor struct{ value *dispatchCursor }
type dispatchCursor struct {
	tenant, owner, after string
	epoch                uint64
}

func (DispatchCursor) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*DispatchCursor) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (DispatchCursor) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.DispatchCursor[private]")
}

type DispatchPage struct {
	Candidates []DispatchCandidate
	Next       *DispatchCursor
}

func (DispatchPage) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }

type dispatchIdentity struct{ tenant, owner string }

func dispatchIdentityFor(ctx context.Context, owner string) (dispatchIdentity, error) {
	if err := ctx.Err(); err != nil {
		return dispatchIdentity{}, err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || !historyID(tenant.String()) || !historyID(owner) || auth.PrincipalFrom(ctx) != nil {
		return dispatchIdentity{}, ErrMessageDenied
	}
	return dispatchIdentity{tenant.String(), owner}, nil
}

func (id dispatchIdentity) authorize(ctx context.Context, authorize AuthorizeDispatch) error {
	current, err := dispatchIdentityFor(ctx, id.owner)
	if err != nil || current != id {
		return messageError(ctx, ErrMessageDenied)
	}
	if authorize == nil {
		return ErrMessageDenied
	}
	if err := authorize(ctx, id.tenant, id.owner); err != nil {
		return messageError(ctx, ErrMessageDenied)
	}
	return ctx.Err()
}

// DispatchPage selects only source-free work metadata and encrypted minimal
// headers. SQL never selects private_payload. Current request Principals are
// refused before the independent internal authorization callback or SQL.
// Owner RLS remains enforced even though no user credential is available yet.
func (j *Journal) DispatchPage(ctx context.Context, owner string, cursor *DispatchCursor, budget DispatchBudget, authorize AuthorizeDispatch) (DispatchPage, error) {
	id, err := dispatchIdentityFor(ctx, owner)
	if err != nil {
		return DispatchPage{}, err
	}
	if budget.Rows <= 0 || budget.HeaderBytes <= 0 || budget.TimeLimit <= 0 {
		return DispatchPage{}, ErrMessageBudget
	}
	window := dispatchCursor{tenant: id.tenant, owner: id.owner, after: "00000000-0000-0000-0000-000000000000"}
	if cursor != nil {
		if cursor.value == nil {
			return DispatchPage{}, ErrJournalConflict
		}
		window = *cursor.value
		if window.tenant != id.tenant || window.owner != id.owner {
			return DispatchPage{}, ErrMessageDenied
		}
		if !historyID(window.after) || window.epoch == 0 || window.epoch > math.MaxInt64 {
			return DispatchPage{}, ErrJournalConflict
		}
	}
	ctx, cancel := context.WithTimeout(ctx, budget.TimeLimit)
	defer cancel()
	if err := id.authorize(ctx, authorize); err != nil {
		return DispatchPage{}, err
	}
	var result DispatchPage
	err = j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		if sc.Tenant.String() != id.tenant {
			return ErrMessageDenied
		}
		if err := bindOwner(ctx, sc, id.owner); err != nil {
			return err
		}
		epoch, err := historyGeneration(ctx, sc)
		if err != nil {
			return err
		}
		if cursor != nil && window.epoch != epoch {
			return ErrJournalGeneration
		}
		window.epoch = epoch
		result, err = readDispatchPage(ctx, sc, window, budget)
		return err
	})
	if err != nil {
		return DispatchPage{}, journalError(ctx, err)
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return DispatchPage{}, err
	}
	return result, nil
}

const dispatchEligible = `j.tenant_id=$1::uuid AND j.owner_id=$2::uuid AND j.epoch=$3
    AND j.job_id>$4::uuid AND (j.status='queued' OR (j.status='processing' AND j.lease_until<=clock_timestamp()))
    AND (m.tenant_id,m.owner_id,m.conversation_id,m.message_id,m.revision)=(j.tenant_id,j.owner_id,j.conversation_id,j.input_message_id,j.input_revision)
    AND m.kind='input' AND m.epoch=j.epoch`

func readDispatchPage(ctx context.Context, sc tenancy.Scope, window dispatchCursor, budget DispatchBudget) (DispatchPage, error) {
	rows, err := sc.Q.Query(ctx, `SELECT tenant_id::text,owner_id::text,conversation_id::text,input_message_id::text,input_revision,epoch,
      job_id::text,status,lease_generation,cancel_revision,size,
      CASE WHEN sum(size) OVER(ORDER BY job_id)<=$6::bigint THEN private_header END
      FROM (SELECT j.tenant_id,j.owner_id,j.conversation_id,j.input_message_id,j.input_revision,j.epoch,
        j.job_id,j.status,j.lease_generation,j.cancel_revision,m.private_header,octet_length(m.private_header)::bigint AS size
        FROM flow_conversation_jobs j,flow_conversation_messages m WHERE `+dispatchEligible+`
        ORDER BY j.job_id LIMIT $5) AS candidates ORDER BY job_id`, window.tenant, window.owner, int64(window.epoch), window.after, budget.Rows, budget.HeaderBytes)
	if err != nil {
		return DispatchPage{}, err
	}
	defer rows.Close()
	var result DispatchPage
	used := 0
	for rows.Next() {
		candidate, bytes, err := scanDispatchCandidate(ctx, rows, window, budget.HeaderBytes-used)
		if err != nil {
			return DispatchPage{}, err
		}
		used += bytes
		window.after = candidate.value.job
		result.Candidates = append(result.Candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return DispatchPage{}, err
	}
	// Close before issuing another query on the same transaction connection.
	rows.Close()
	var more bool
	if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_conversation_jobs j,flow_conversation_messages m WHERE `+dispatchEligible+`)`, window.tenant, window.owner, int64(window.epoch), window.after).Scan(&more); err != nil {
		return DispatchPage{}, err
	}
	if more {
		result.Next = &DispatchCursor{&window}
	}
	return result, nil
}

func scanDispatchCandidate(ctx context.Context, row historyRow, window dispatchCursor, budget int) (DispatchCandidate, int, error) {
	var result dispatchCandidate
	var revision, epoch, generation, cancellation, size int64
	var header *string
	if err := row.Scan(&result.scope.TenantID, &result.scope.OwnerID, &result.scope.ConversationID, &result.scope.MessageID, &revision, &epoch,
		&result.job, &result.status, &generation, &cancellation, &size, &header); err != nil {
		return DispatchCandidate{}, 0, err
	}
	if size > int64(budget) {
		return DispatchCandidate{}, 0, ErrMessageBudget
	}
	if size < 0 || revision <= 0 || epoch <= 0 || generation < 0 || cancellation < 0 || header == nil || int64(len(*header)) != size {
		return DispatchCandidate{}, 0, ErrMessageIntegrity
	}
	result.scope.Revision, result.scope.Epoch = uint64(revision), uint64(epoch)
	result.generation, result.cancellation = uint64(generation), uint64(cancellation)
	if err := result.scope.validate(ctx); err != nil {
		return DispatchCandidate{}, 0, err
	}
	if result.scope.TenantID != window.tenant || result.scope.OwnerID != window.owner || result.scope.Epoch != window.epoch ||
		!historyID(result.job) || result.job <= window.after || (result.status != "queued" && result.status != "processing") {
		return DispatchCandidate{}, 0, ErrMessageIntegrity
	}
	// Unknown/corrupt headers remain opaque metadata so independent terminal
	// cleanup is possible. BootstrapDispatch must authenticate them separately.
	result.header = *header
	return DispatchCandidate{&result}, int(size), nil
}
