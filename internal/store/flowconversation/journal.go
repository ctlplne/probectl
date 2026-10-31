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
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrJournalConflict    = errors.New("flow conversation: immutable history changed or is unavailable")
	ErrJournalGeneration  = errors.New("flow conversation: lifecycle generation changed")
	ErrJournalUnavailable = errors.New("flow conversation: private history storage unavailable")
)

// Revision identifies an immutable parent within the same tenant, owner and
// conversation. No implicit latest-message lookup participates in admission.
type Revision struct {
	MessageID string
	Revision  uint64
}

// InputMetadata contains no source text. FrozenAt is the server's original
// interpretation clock; ExpiresAt comes from authoritative retention policy.
// Zero is that policy's keep-forever choice, never a question/model flag.
type InputMetadata struct {
	Parent              *Revision
	FrozenAt, ExpiresAt time.Time
}

// PreparedInput can only be built after scoped encryption outside SQL locks.
// It is not JSON, authority, a bearer capability, or a public request body.
type PreparedInput struct{ input *preparedInput }
type preparedInput struct {
	scope    MessageScope
	meta     InputMetadata
	sealed   SealedMessage
	origin   auth.WorkerCredentialRef
	jobID    string
	required []string
}

func (PreparedInput) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*PreparedInput) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (PreparedInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.PreparedInput[private]")
}

// PrepareInput admits no permission by itself. The service must derive the
// complete source-dependency union and validate sources before calling it.
// authorize revalidates that operation's exact current origin/requirements;
// no SQL transaction or model call may be held across this crypto operation.
func (c *Codec) PrepareInput(ctx context.Context, scope MessageScope, meta InputMetadata, requirements []string, body []byte, authorize AuthorizeMessage) (PreparedInput, error) {
	if err := scope.validate(ctx); err != nil {
		return PreparedInput{}, err
	}
	origin, err := requestOrigin(ctx, scope.TenantID, scope.OwnerID)
	if err != nil {
		return PreparedInput{}, err
	}
	meta.FrozenAt, meta.ExpiresAt = meta.FrozenAt.UTC(), StorageDeadline(meta.ExpiresAt)
	if scope.Revision > math.MaxInt64 || scope.Epoch > math.MaxInt64 || !validInputMetadata(scope, meta) || authorize == nil {
		return PreparedInput{}, ErrMessageIntegrity
	}
	// Freeze caller-owned metadata/source before crossing an external port.
	if meta.Parent != nil {
		parent := *meta.Parent
		meta.Parent = &parent
	}
	if err := c.available(); err != nil {
		return PreparedInput{}, err
	}
	if len(body) > c.budget.PlainBytes {
		return PreparedInput{}, ErrMessageBudget
	}
	plain := bytes.Clone(body)
	defer clear(plain)
	required, err := canonicalMessageRequirements(requirements, c.budget.HeaderBytes)
	if err != nil {
		return PreparedInput{}, err
	}
	if err := authorize(ctx, scope, origin, append([]string(nil), required...)); err != nil {
		return PreparedInput{}, messageError(ctx, ErrMessageDenied)
	}
	sealed, err := c.Seal(ctx, scope, origin, required, plain)
	if err != nil {
		return PreparedInput{}, err
	}
	if err := authorize(ctx, scope, origin, append([]string(nil), required...)); err != nil {
		return PreparedInput{}, messageError(ctx, ErrMessageDenied)
	}
	if err := ctx.Err(); err != nil {
		return PreparedInput{}, err
	}
	jobID, err := crypto.UUIDv4()
	if err != nil {
		return PreparedInput{}, ErrJournalUnavailable
	}
	if err := ctx.Err(); err != nil {
		return PreparedInput{}, err
	}
	return PreparedInput{&preparedInput{scope: scope, meta: meta, sealed: sealed, origin: origin, jobID: jobID, required: required}}, nil
}

func validInputMetadata(scope MessageScope, meta InputMetadata) bool {
	if meta.FrozenAt.IsZero() || !meta.ExpiresAt.IsZero() && !meta.ExpiresAt.After(meta.FrozenAt) {
		return false
	}
	if meta.Parent == nil {
		return true
	}
	parent := meta.Parent
	id, err := uuid.Parse(parent.MessageID)
	return err == nil && id.String() == parent.MessageID && parent.Revision > 0 && parent.Revision <= math.MaxInt64 &&
		(parent.MessageID != scope.MessageID || parent.Revision != scope.Revision)
}

// StorageDeadline preserves no-deadline policy and floors finite deadlines to
// PostgreSQL precision. Rounding must never extend authorized retention.
func StorageDeadline(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Truncate(time.Microsecond)
}

func requestOrigin(ctx context.Context, tenant, owner string) (auth.WorkerCredentialRef, error) {
	if err := ctx.Err(); err != nil {
		return auth.WorkerCredentialRef{}, err
	}
	amb, ok := tenancy.FromContext(ctx)
	p := auth.PrincipalFrom(ctx)
	if !ok || amb.String() != tenant || p == nil || p.TenantID != tenant || p.UserID != owner {
		return auth.WorkerCredentialRef{}, ErrMessageDenied
	}
	ref, err := auth.WorkerCredentialFromPrincipal(p)
	if err != nil {
		return auth.WorkerCredentialRef{}, ErrMessageDenied
	}
	return ref, nil
}

func sameRequestOrigin(a, b auth.WorkerCredentialRef) bool {
	left, err := a.MarshalBinary()
	if err != nil {
		return false
	}
	defer clear(left)
	right, err := b.MarshalBinary()
	if err != nil {
		return false
	}
	defer clear(right)
	return crypto.ConstantTimeEqual(left, right)
}

// Journal owns routed tenant transactions and the canonical writer fence.
// No method executes model/crypto/auth callbacks while holding mutation locks.
type Journal struct {
	pool   *pgxpool.Pool
	fence  tenancy.WriterFence
	record func(context.Context, tenancy.Scope, string, string, string, map[string]any) error
}

func NewJournal(pool *pgxpool.Pool) *Journal {
	return &Journal{pool: pool, fence: tenancy.NewPostgresWriterFence(pool), record: audit.TenantRecord}
}

func (j *Journal) available() error {
	if j == nil || j.pool == nil || j.fence == nil || j.record == nil {
		return ErrJournalUnavailable
	}
	return nil
}

func (j *Journal) scoped(ctx context.Context, fn func(context.Context, tenancy.Scope) error) error {
	if err := j.available(); err != nil {
		return err
	}
	return tenancy.InTenant(tenancy.WithSiloTableLock(ctx), j.pool, fn)
}

func bindRequestOwner(ctx context.Context, sc tenancy.Scope) (string, auth.WorkerCredentialRef, error) {
	if err := validOwnerScope(ctx, sc); err != nil {
		return "", auth.WorkerCredentialRef{}, err
	}
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return "", auth.WorkerCredentialRef{}, ErrMessageDenied
	}
	ref, err := requestOrigin(ctx, sc.Tenant.String(), p.UserID)
	if err != nil {
		return "", auth.WorkerCredentialRef{}, err
	}
	if err := bindOwner(ctx, sc, p.UserID); err != nil {
		return "", auth.WorkerCredentialRef{}, err
	}
	return p.UserID, ref, nil
}

// CandidateEpoch never creates state. The first atomic admission initializes
// generation1; a missing registry tenant or later lifecycle fence still refuses
// at commit. Erasure must retain/advance this marker until full tenant teardown.
func (j *Journal) CandidateEpoch(ctx context.Context) (uint64, error) {
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return 0, ErrMessageDenied
	}
	if _, err := requestOrigin(ctx, p.TenantID, p.UserID); err != nil {
		return 0, err
	}
	var result uint64
	err := j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = candidateEpoch(ctx, sc)
		return err
	})
	if err != nil {
		return 0, journalError(ctx, err)
	}
	return result, nil
}

func candidateEpoch(ctx context.Context, sc tenancy.Scope) (uint64, error) {
	if _, _, err := bindRequestOwner(ctx, sc); err != nil {
		return 0, err
	}
	return activeConversationEpoch(ctx, sc, epochRead)
}

// AdmitInput atomically appends one immutable input, its queued job and audit.
// The canonical writer fence precedes the audit stream and epoch/message rows,
// matching subject/full lifecycle lock order. Current credential/source
// authorization precedes this short transaction.
func (j *Journal) AdmitInput(ctx context.Context, prepared PreparedInput, authorize AuthorizeMessage) error {
	in := prepared.input
	if in == nil || authorize == nil {
		return ErrMessageDenied
	}
	origin, err := requestOrigin(ctx, in.scope.TenantID, in.scope.OwnerID)
	if err != nil {
		return err
	}
	if !sameRequestOrigin(origin, in.origin) {
		return ErrMessageDenied
	}
	if err := j.available(); err != nil {
		return err
	}
	if err := authorize(ctx, in.scope, in.origin, append([]string(nil), in.required...)); err != nil {
		return messageError(ctx, ErrMessageDenied)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return j.fence.WithTenantWrites(ctx, []string{in.scope.TenantID}, func(ctx context.Context) error {
		return j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
			return j.admitInput(ctx, sc, prepared)
		})
	})
}

func (j *Journal) admitInput(ctx context.Context, sc tenancy.Scope, prepared PreparedInput) error {
	owner, origin, err := bindRequestOwner(ctx, sc)
	if err != nil {
		return err
	}
	in := prepared.input
	if in == nil || in.sealed.parts == nil || in.scope.TenantID != sc.Tenant.String() || in.scope.OwnerID != owner || !sameRequestOrigin(in.origin, origin) {
		return ErrMessageDenied
	}
	if err := in.scope.validate(ctx); err != nil {
		return err
	}
	if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
		return journalError(ctx, err)
	}
	if _, err := sc.Q.Exec(ctx, `INSERT INTO flow_conversation_epochs(tenant_id,generation) VALUES($1::uuid,1) ON CONFLICT (tenant_id) DO NOTHING`, sc.Tenant.String()); err != nil {
		return journalError(ctx, err)
	}
	generation, err := activeConversationEpoch(ctx, sc, epochUpdate)
	if err != nil {
		return journalError(ctx, err)
	}
	if generation != in.scope.Epoch {
		return ErrJournalGeneration
	}
	if err := checkInputParent(ctx, sc, in); err != nil {
		return err
	}
	var parentID any
	var parentRevision any
	var expires any
	if in.meta.Parent != nil {
		parentID, parentRevision = in.meta.Parent.MessageID, int64(in.meta.Parent.Revision)
	}
	if !in.meta.ExpiresAt.IsZero() {
		expires = in.meta.ExpiresAt
	}
	tag, err := sc.Q.Exec(ctx, `INSERT INTO flow_conversation_messages(tenant_id,owner_id,conversation_id,message_id,revision,epoch,parent_message_id,parent_revision,kind,frozen_at,expires_at,private_header,private_payload,position)
        SELECT $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7::uuid,$8,'input',$9,$10::timestamptz,$11,$12,
          COALESCE((SELECT max(position) FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid),0)+1
        WHERE ($10::timestamptz IS NULL OR $10::timestamptz>clock_timestamp())`,
		in.scope.TenantID, owner, in.scope.ConversationID, in.scope.MessageID, int64(in.scope.Revision), int64(in.scope.Epoch), parentID, parentRevision,
		in.meta.FrozenAt.UTC().Format(time.RFC3339Nano), expires, in.sealed.parts.header, in.sealed.parts.payload)
	if err != nil {
		return journalError(ctx, err)
	}
	if tag.RowsAffected() != 1 {
		return ErrJournalConflict
	}
	_, err = sc.Q.Exec(ctx, `INSERT INTO flow_conversation_jobs(tenant_id,owner_id,conversation_id,job_id,input_message_id,input_revision,epoch,status,lease_generation)
        VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7,'queued',0)`,
		in.scope.TenantID, owner, in.scope.ConversationID, in.jobID, in.scope.MessageID, int64(in.scope.Revision), int64(in.scope.Epoch))
	if err != nil {
		return journalError(ctx, err)
	}
	return journalError(ctx, j.record(ctx, sc, owner, "flow.conversation.input", in.scope.MessageID, map[string]any{
		"conversation_id": in.scope.ConversationID, "message_revision": in.scope.Revision, "generation": in.scope.Epoch, "job_id": in.jobID,
	}))
}

func checkInputParent(ctx context.Context, sc tenancy.Scope, in *preparedInput) error {
	if in.meta.Parent == nil {
		return nil
	}
	var live bool
	var expires any
	if !in.meta.ExpiresAt.IsZero() {
		expires = in.meta.ExpiresAt
	}
	err := sc.Q.QueryRow(ctx, `SELECT (expires_at IS NULL OR (expires_at>clock_timestamp() AND $6::timestamptz IS NOT NULL AND $6::timestamptz<=expires_at)) FROM flow_conversation_messages
        WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid AND message_id=$4::uuid AND revision=$5 FOR KEY SHARE`,
		in.scope.TenantID, in.scope.OwnerID, in.scope.ConversationID, in.meta.Parent.MessageID, int64(in.meta.Parent.Revision), expires).Scan(&live)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !live {
		return ErrJournalConflict
	}
	return journalError(ctx, err)
}

func journalError(ctx context.Context, err error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrJournalConflict
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) && (databaseError.Code == "23505" || databaseError.Code == "23503") {
		return ErrJournalConflict
	}
	if errors.Is(err, ErrMessageDenied) || errors.Is(err, ErrMessageIntegrity) || errors.Is(err, ErrMessageBudget) || errors.Is(err, ErrJournalConflict) || errors.Is(err, ErrJournalGeneration) || errors.Is(err, ErrJournalUnavailable) || errors.Is(err, ErrJournalLease) {
		return err
	}
	return ErrJournalUnavailable
}
