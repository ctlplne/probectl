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

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

// AuthorizeHistory must reload the operation's exact current owner credential
// and base history permissions. StoredMessage still requires the separate
// current-owner Codec.Open callback for every authenticated source dependency.
// This metadata operation never opens source or revives stored-origin jobs.
type AuthorizeHistory func(context.Context, string, string, auth.WorkerCredentialRef) error

// HistoryBudget limits one page's cost, never total retained history or turns.
// Callers supply positive operator resources; no silent truncation on bytes.
type HistoryBudget struct{ Rows, Bytes int }

// StoredMessage is a private immutable storage reference, not public history.
// Metadata is an index/display projection, not independent query authority.
type StoredMessage struct{ value *storedMessage }
type storedMessage struct {
	scope    MessageScope
	meta     InputMetadata
	kind     string
	position uint64
	sealed   SealedMessage
}

func (StoredMessage) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*StoredMessage) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (StoredMessage) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.StoredMessage[private]")
}
func (m StoredMessage) Scope() MessageScope {
	if m.value == nil {
		return MessageScope{}
	}
	return m.value.scope
}
func (m StoredMessage) Metadata() InputMetadata {
	if m.value == nil {
		return InputMetadata{}
	}
	result := m.value.meta
	if result.Parent != nil {
		parent := *result.Parent
		result.Parent = &parent
	}
	return result
}
func (m StoredMessage) Kind() string {
	if m.value == nil {
		return ""
	}
	return m.value.kind
}
func (m StoredMessage) Ciphertext() SealedMessage {
	if m.value == nil {
		return SealedMessage{}
	}
	return m.value.sealed
}

// Position and StoredBytes are private scoped index/resource metadata, never
// a public continuation or permission to open the encrypted record.
func (m StoredMessage) Position() uint64 {
	if m.value == nil {
		return 0
	}
	return m.value.position
}
func (m StoredMessage) StoredBytes() int {
	if m.value == nil || m.value.sealed.parts == nil {
		return 0
	}
	return len(m.value.sealed.parts.header) + len(m.value.sealed.parts.payload)
}

// HistoryCursor is an in-process continuation, never a public/wire capability.
// Reauthentication by the same owner is allowed after fresh authorization.
type HistoryCursor struct{ window *historyWindow }
type historyWindow struct {
	tenant, owner, conversation string
	after, upper, generation    uint64
	validUntil                  time.Time
}

func (HistoryCursor) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*HistoryCursor) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (HistoryCursor) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.HistoryCursor[private]")
}

type HistoryPage struct {
	Messages []StoredMessage
	Next     *HistoryCursor
}

func (HistoryPage) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }

type historyIdentity struct {
	tenant, owner string
	origin        auth.WorkerCredentialRef
}

func historyIdentityFor(ctx context.Context) (historyIdentity, error) {
	p := auth.PrincipalFrom(ctx)
	if p == nil {
		return historyIdentity{}, ErrMessageDenied
	}
	ref, err := requestOrigin(ctx, p.TenantID, p.UserID)
	if err != nil {
		return historyIdentity{}, err
	}
	return historyIdentity{tenant: p.TenantID, owner: p.UserID, origin: ref}, nil
}

func (id historyIdentity) authorize(ctx context.Context, authorize AuthorizeHistory) error {
	if authorize == nil {
		return ErrMessageDenied
	}
	if err := authorize(ctx, id.tenant, id.owner, id.origin); err != nil {
		return messageError(ctx, ErrMessageDenied)
	}
	current, err := historyIdentityFor(ctx)
	if err != nil {
		return err
	}
	if current.tenant != id.tenant || current.owner != id.owner || !sameRequestOrigin(current.origin, id.origin) {
		return ErrMessageDenied
	}
	return nil
}

func historyID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id.String() == value
}

// Lookup returns only one currently retained same-owner private record. It
// performs no decryption. Callers must open it with current dependency/source
// authority and revalidate lifecycle/publication before exposing plaintext.
func (j *Journal) Lookup(ctx context.Context, conversation string, revision Revision, bytes int, authorize AuthorizeHistory) (StoredMessage, error) {
	id, err := historyIdentityFor(ctx)
	if err != nil {
		return StoredMessage{}, err
	}
	if !historyID(conversation) || !historyID(revision.MessageID) || revision.Revision == 0 || revision.Revision > math.MaxInt64 {
		return StoredMessage{}, ErrJournalConflict
	}
	if bytes <= 0 {
		return StoredMessage{}, ErrMessageBudget
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return StoredMessage{}, err
	}
	var result StoredMessage
	err = j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		if _, _, err := bindRequestOwner(ctx, sc); err != nil {
			return err
		}
		if _, err := activeConversationEpoch(ctx, sc, epochShare); err != nil {
			return err
		}
		var err error
		result, _, err = scanStoredMessage(ctx, sc.Q.QueryRow(ctx, `SELECT `+historyColumns+`
          FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid
          AND message_id=$4::uuid AND revision=$5 AND `+historyRetained, id.tenant, id.owner, conversation, revision.MessageID, int64(revision.Revision), bytes), id, conversation, bytes)
		return err
	})
	if err != nil {
		return StoredMessage{}, journalError(ctx, err)
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return StoredMessage{}, err
	}
	return result, nil
}

// Page captures an upper bound on the first page and uses conversation-local
// immutable positions. Later appends cannot shift the traversal. Changed
// lifecycle generations refuse continuation rather than silently skipping rows.
func (j *Journal) Page(ctx context.Context, conversation string, cursor *HistoryCursor, budget HistoryBudget, authorize AuthorizeHistory) (HistoryPage, error) {
	id, err := historyIdentityFor(ctx)
	if err != nil {
		return HistoryPage{}, err
	}
	if !historyID(conversation) {
		return HistoryPage{}, ErrJournalConflict
	}
	if budget.Rows <= 0 || budget.Bytes <= 0 {
		return HistoryPage{}, ErrMessageBudget
	}
	var window historyWindow
	if cursor != nil {
		if cursor.window == nil {
			return HistoryPage{}, ErrJournalConflict
		}
		window = *cursor.window
		if window.tenant != id.tenant || window.owner != id.owner || window.conversation != conversation {
			return HistoryPage{}, ErrMessageDenied
		}
		if window.after == 0 || window.after >= window.upper || window.upper > math.MaxInt64 || window.generation == 0 || window.generation > math.MaxInt64 {
			return HistoryPage{}, ErrJournalConflict
		}
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return HistoryPage{}, err
	}
	var result HistoryPage
	err = j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		if _, _, err := bindRequestOwner(ctx, sc); err != nil {
			return err
		}
		generation, err := historyGeneration(ctx, sc)
		if err != nil {
			return err
		}
		if cursor == nil {
			window = historyWindow{tenant: id.tenant, owner: id.owner, conversation: conversation, generation: generation}
			var deadline *time.Time
			if err := sc.Q.QueryRow(ctx, `SELECT COALESCE(max(position),0),min(expires_at) FROM flow_conversation_messages
              WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid AND `+historyRetained, id.tenant, id.owner, conversation).Scan(&window.upper, &deadline); err != nil {
				return err
			}
			if deadline != nil {
				window.validUntil = *deadline
			}
		} else if generation != window.generation {
			return ErrJournalGeneration
		}
		result, err = readHistoryPage(ctx, sc, id, window, budget)
		if err != nil {
			return err
		}
		if window.upper != 0 && !window.validUntil.IsZero() {
			var live bool
			if err := sc.Q.QueryRow(ctx, `SELECT $1::timestamptz>clock_timestamp()`, window.validUntil).Scan(&live); err != nil {
				return err
			}
			if !live {
				return ErrJournalConflict
			}
		}
		return nil
	})
	if err != nil {
		return HistoryPage{}, journalError(ctx, err)
	}
	if err := id.authorize(ctx, authorize); err != nil {
		return HistoryPage{}, err
	}
	return result, nil
}

func historyGeneration(ctx context.Context, sc tenancy.Scope) (uint64, error) {
	return activeConversationEpoch(ctx, sc, epochShare)
}

// Length and cumulative page cost are computed server-side; ciphertext that
// would exceed the page resource is not transferred merely to reject it in Go.
const historyStoredBytes = `octet_length(private_header)::bigint+octet_length(private_payload)::bigint`
const historyRetained = `(expires_at IS NULL OR expires_at>clock_timestamp())`
const historyColumnsBase = `tenant_id::text,owner_id::text,conversation_id::text,message_id::text,revision,epoch,
    parent_message_id::text,parent_revision,kind,frozen_at,expires_at,position,` + historyStoredBytes
const historyColumns = historyColumnsBase + `,
    CASE WHEN ` + historyStoredBytes + `<=$6 THEN private_header END,
    CASE WHEN ` + historyStoredBytes + `<=$6 THEN private_payload END`
const historyPageColumns = historyColumnsBase + `,
    CASE WHEN sum(` + historyStoredBytes + `) OVER(ORDER BY position)<=$6 THEN private_header END,
    CASE WHEN sum(` + historyStoredBytes + `) OVER(ORDER BY position)<=$6 THEN private_payload END`

func readHistoryPage(ctx context.Context, sc tenancy.Scope, id historyIdentity, window historyWindow, budget HistoryBudget) (HistoryPage, error) {
	if window.upper == 0 {
		return HistoryPage{}, nil
	}
	rows, err := sc.Q.Query(ctx, `SELECT `+historyPageColumns+` FROM (SELECT * FROM flow_conversation_messages
      WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid AND position>$4 AND position<=$5
      AND `+historyRetained+` ORDER BY position LIMIT $7) AS page_candidates ORDER BY position`, id.tenant, id.owner, window.conversation, int64(window.after), int64(window.upper), budget.Bytes, budget.Rows)
	if err != nil {
		return HistoryPage{}, err
	}
	defer rows.Close()
	var result HistoryPage
	used := 0
	for rows.Next() {
		message, bytes, err := scanStoredMessage(ctx, rows, id, window.conversation, budget.Bytes-used)
		if err != nil {
			return HistoryPage{}, err
		}
		if message.value.position <= window.after || message.value.position > window.upper {
			return HistoryPage{}, ErrMessageIntegrity
		}
		used += bytes
		result.Messages = append(result.Messages, message)
		window.after = message.value.position
	}
	if err := rows.Err(); err != nil {
		return HistoryPage{}, err
	}
	rows.Close()
	var more bool
	if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND owner_id=$2::uuid
      AND conversation_id=$3::uuid AND position>$4 AND position<=$5 AND `+historyRetained+`)`, id.tenant, id.owner, window.conversation, int64(window.after), int64(window.upper)).Scan(&more); err != nil {
		return HistoryPage{}, err
	}
	if more {
		result.Next = &HistoryCursor{&window}
	}
	return result, nil
}

type historyRow interface{ Scan(...any) error }

func scanStoredMessage(ctx context.Context, row historyRow, identity historyIdentity, conversation string, budget int) (StoredMessage, int, error) {
	message, size, err := scanTenantMessage(ctx, row, budget)
	if err != nil {
		return StoredMessage{}, 0, err
	}
	if message.value.scope.TenantID != identity.tenant || message.value.scope.OwnerID != identity.owner || message.value.scope.ConversationID != conversation {
		return StoredMessage{}, 0, ErrMessageIntegrity
	}
	return message, size, nil
}

// The tenant-only decoder is private to controlled lifecycle readers. Ordinary
// owner lookup/page callers retain the exact owner/conversation wrapper above.
func scanTenantMessage(ctx context.Context, row historyRow, budget int) (StoredMessage, int, error) {
	var result storedMessage
	var revision, epoch, position, size int64
	var parentID, header, payload *string
	var parentRevision *int64
	var frozen string
	var expires *time.Time
	if err := row.Scan(&result.scope.TenantID, &result.scope.OwnerID, &result.scope.ConversationID, &result.scope.MessageID, &revision, &epoch,
		&parentID, &parentRevision, &result.kind, &frozen, &expires, &position, &size, &header, &payload); err != nil {
		return StoredMessage{}, 0, err
	}
	if size <= 0 || size > int64(budget) {
		return StoredMessage{}, 0, ErrMessageBudget
	}
	if revision <= 0 || epoch <= 0 || position <= 0 || header == nil || payload == nil || int64(len(*header))+int64(len(*payload)) != size {
		return StoredMessage{}, 0, ErrMessageIntegrity
	}
	result.scope.Revision, result.scope.Epoch, result.position = uint64(revision), uint64(epoch), uint64(position)
	if expires != nil {
		result.meta.ExpiresAt = *expires
	}
	if err := result.scope.validate(ctx); err != nil {
		return StoredMessage{}, 0, err
	}
	if (parentID == nil) != (parentRevision == nil) {
		return StoredMessage{}, 0, ErrMessageIntegrity
	}
	var err error
	result.meta.FrozenAt, err = time.Parse(time.RFC3339Nano, frozen)
	if err != nil || result.meta.FrozenAt.UTC().Format(time.RFC3339Nano) != frozen {
		return StoredMessage{}, 0, ErrMessageIntegrity
	}
	if parentID != nil {
		if *parentRevision <= 0 {
			return StoredMessage{}, 0, ErrMessageIntegrity
		}
		result.meta.Parent = &Revision{MessageID: *parentID, Revision: uint64(*parentRevision)}
	}
	if !validInputMetadata(result.scope, result.meta) || !historyKind(result.kind) || !tenantcrypto.HasScheme(*header) || !tenantcrypto.HasScheme(*payload) {
		return StoredMessage{}, 0, ErrMessageIntegrity
	}
	result.sealed = SealedMessage{&sealedMessageParts{header: *header, payload: *payload}}
	return StoredMessage{&result}, int(size), nil
}

func historyKind(kind string) bool {
	return kind == "input" || kind == "proposal" || kind == "result" || kind == "confirmation"
}
