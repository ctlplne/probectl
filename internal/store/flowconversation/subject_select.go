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
	"slices"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The application must validate the complete typed frame and its immutable
// index bindings before returning a semantic match. A match is never authority.
// body and plan are borrowed only for this joined source phase; release clears
// application-owned matching state. There is deliberately no generic fallback.
type SubjectDocumentMatch func(context.Context, StoredMessage, []byte) (bool, error)
type SubjectMatchFactory func(context.Context, SubjectErasurePlan) (SubjectDocumentMatch, func(), error)

type subjectDocumentMatch = SubjectDocumentMatch
type subjectMatchFactory = SubjectMatchFactory

// This bounded set holds exact original ciphertext pairs, not decoded source,
// a completed erasure receipt or permission to clear the durable intent.
type subjectLeafSelection struct {
	pending   Invalidation
	leaves    []StoredMessage
	scanned   int64
	exhausted bool
}

func (subjectLeafSelection) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*subjectLeafSelection) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (subjectLeafSelection) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.subjectLeafSelection[private]")
}

func (j *Journal) selectSubjectLeaves(ctx context.Context, codec *Codec, pending Invalidation, budget HistoryBudget, authorize AuthorizeMaintenance, factory subjectMatchFactory) (subjectLeafSelection, error) {
	if budget.Rows <= 0 || budget.Bytes <= 0 {
		return subjectLeafSelection{}, ErrMessageBudget
	}
	if factory == nil {
		return subjectLeafSelection{}, ErrMessageDenied
	}
	var result subjectLeafSelection
	err := j.withSubjectMatchSource(ctx, codec, pending, authorize, func(ctx context.Context, plan SubjectErasurePlan) error {
		return j.withSubjectReader(ctx, func(ctx context.Context) error {
			match, release, err := factory(ctx, plan)
			if release != nil {
				defer release()
			}
			if err != nil {
				return err
			}
			if match == nil || release == nil {
				return ErrMessageDenied
			}
			result, err = j.scanSubjectLeaves(ctx, codec, plan, budget, match)
			return err
		})
	})
	if err != nil {
		// An eventual failure, ignored callback error or missing drain can
		// never publish a partial set as a successful empty/complete scan.
		return subjectLeafSelection{}, err
	}
	result.pending = pending
	return result, nil
}

func (j *Journal) scanSubjectLeaves(ctx context.Context, codec *Codec, plan SubjectErasurePlan, budget HistoryBudget, match subjectDocumentMatch) (subjectLeafSelection, error) {
	var result subjectLeafSelection
	var after exportPosition
	selectedBytes := 0
	for {
		page, used, err := j.subjectHistoryPage(ctx, after, budget)
		if err != nil {
			return subjectLeafSelection{}, err
		}
		if len(page) == 0 {
			result.exhausted = true
			return result, nil
		}
		remaining := budget.Bytes - used
		for _, stored := range page {
			if result.scanned == math.MaxInt64 {
				return subjectLeafSelection{}, ErrMessageBudget
			}
			selected, err := j.matchSubjectAncestry(ctx, codec, stored, plan, &remaining, match)
			if err != nil {
				return subjectLeafSelection{}, err
			}
			result.scanned++
			after = exportPosition{stored.value.scope.OwnerID, stored.value.scope.ConversationID, stored.value.scope.MessageID, stored.value.scope.Revision}
			if !selected {
				continue
			}
			leaf, err := j.subjectHistoryLeaf(ctx, stored)
			if err != nil {
				return subjectLeafSelection{}, err
			}
			if !leaf {
				continue
			}
			if stored.StoredBytes() > budget.Bytes-selectedBytes {
				return result, nil // bounded selection; explicitly not EOF
			}
			result.leaves = append(result.leaves, stored)
			selectedBytes += stored.StoredBytes()
			if len(result.leaves) == budget.Rows {
				return result, nil
			}
		}
	}
}

// Fixed destructive-purpose query: intentionally no historyRetained predicate.
// Materialize only a bounded encrypted page and close SQL before any callback,
// decryption or complete ancestry walk (which needs its own short SQL reads).
func (j *Journal) subjectHistoryPage(ctx context.Context, after exportPosition, budget HistoryBudget) ([]StoredMessage, int, error) {
	var page []StoredMessage
	used := 0
	err := j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		if err := bindLifecycle(ctx, sc); err != nil {
			return err
		}
		columns := historyColumnsBase + `,
 CASE WHEN sum(` + historyStoredBytes + `) OVER(ORDER BY owner_id,conversation_id,message_id,revision)<=$7 THEN private_header END,
 CASE WHEN sum(` + historyStoredBytes + `) OVER(ORDER BY owner_id,conversation_id,message_id,revision)<=$7 THEN private_payload END`
		var owner, conversation, message any
		if after.owner != "" {
			owner, conversation, message = after.owner, after.conversation, after.message
		}
		rows, err := sc.Q.Query(ctx, `SELECT `+columns+` FROM (SELECT * FROM flow_conversation_messages
 WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR (owner_id,conversation_id,message_id,revision)>($2::uuid,$3::uuid,$4::uuid,$5))
 ORDER BY owner_id,conversation_id,message_id,revision LIMIT $6) AS subject_candidates
 ORDER BY owner_id,conversation_id,message_id,revision`, sc.Tenant.String(), owner, conversation, message, int64(after.revision), budget.Rows, budget.Bytes)
		if err != nil {
			return err
		}
		defer rows.Close()
		last := after
		for rows.Next() {
			stored, size, err := scanTenantMessage(ctx, rows, budget.Bytes-used)
			if err != nil {
				return err
			}
			position := exportPosition{stored.value.scope.OwnerID, stored.value.scope.ConversationID, stored.value.scope.MessageID, stored.value.scope.Revision}
			if len(page) >= budget.Rows || !exportPositionAfter(position, last) {
				return ErrMessageIntegrity
			}
			page = append(page, stored)
			used += size
			last = position
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, journalError(ctx, err)
	}
	return page, used, nil
}

func (j *Journal) matchSubjectAncestry(ctx context.Context, codec *Codec, stored StoredMessage, plan SubjectErasurePlan, remaining *int, match subjectDocumentMatch) (bool, error) {
	if plan.value == nil {
		return false, ErrMessageDenied
	}
	selected := slices.Contains(plan.value.wire.Aliases, stored.value.scope.OwnerID)
	for {
		current, err := j.matchSubjectDocument(ctx, codec, stored, match)
		if err != nil {
			return false, err
		}
		selected = selected || current
		// Never short-circuit a direct/owner match: every ancestor document
		// and immediate edge remains an integrity requirement.
		if stored.value.meta.Parent == nil {
			return selected, nil
		}
		if remaining == nil || *remaining <= 0 {
			return false, ErrMessageBudget
		}
		parent, err := j.subjectHistoryAncestor(ctx, stored, *remaining)
		if err != nil {
			return false, err
		}
		*remaining -= parent.StoredBytes()
		stored = parent
	}
}

func (j *Journal) matchSubjectDocument(ctx context.Context, codec *Codec, stored StoredMessage, match subjectDocumentMatch) (bool, error) {
	lease, _ := ctx.Value(subjectSourceLeaseKey{}).(*subjectSourceLease)
	check := func(ctx context.Context) error { return j.checkSubjectSource(ctx, lease) }
	if err := check(ctx); err != nil {
		return false, err
	}
	body, err := codec.Open(ctx, stored.value.scope, stored.value.sealed, func(ctx context.Context, scope MessageScope, _ auth.WorkerCredentialRef, _ []string) error {
		if scope != stored.value.scope {
			return ErrMessageDenied
		}
		// Independent current privacy authority, never a stored origin grant.
		return check(ctx)
	})
	if err != nil {
		return false, err
	}
	defer clear(body)
	selected, err := match(ctx, stored, body)
	if err != nil {
		return false, err
	}
	return selected, check(ctx)
}

func (j *Journal) subjectHistoryAncestor(ctx context.Context, child StoredMessage, budget int) (StoredMessage, error) {
	value := child.value
	if value == nil || value.meta.Parent == nil || !validWorkInput(value.scope.ConversationID, *value.meta.Parent) {
		return StoredMessage{}, ErrMessageIntegrity
	}
	var parent StoredMessage
	err := j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		if err := bindLifecycle(ctx, sc); err != nil {
			return err
		}
		var err error
		parent, _, err = scanStoredMessage(ctx, sc.Q.QueryRow(ctx, `SELECT `+historyColumns+` FROM flow_conversation_messages
 WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid AND message_id=$4::uuid AND revision=$5`, value.scope.TenantID, value.scope.OwnerID, value.scope.ConversationID, value.meta.Parent.MessageID, int64(value.meta.Parent.Revision), budget), historyIdentity{tenant: value.scope.TenantID, owner: value.scope.OwnerID}, value.scope.ConversationID, budget)
		return err
	})
	if err != nil {
		return StoredMessage{}, journalError(ctx, err)
	}
	if !subjectParentEdge(child, parent) {
		return StoredMessage{}, ErrMessageIntegrity
	}
	return parent, nil
}

func subjectParentEdge(child, parent StoredMessage) bool {
	c, p := child.value, parent.value
	return c != nil && p != nil && c.meta.Parent != nil &&
		c.scope.TenantID == p.scope.TenantID && c.scope.OwnerID == p.scope.OwnerID && c.scope.ConversationID == p.scope.ConversationID &&
		c.meta.Parent.MessageID == p.scope.MessageID && c.meta.Parent.Revision == p.scope.Revision &&
		p.position > 0 && p.position < c.position && p.scope.Epoch > 0 && p.scope.Epoch <= c.scope.Epoch && !p.meta.FrozenAt.After(c.meta.FrozenAt)
}

func (j *Journal) subjectHistoryLeaf(ctx context.Context, stored StoredMessage) (bool, error) {
	var leaf bool
	err := j.scoped(ctx, func(ctx context.Context, sc tenancy.Scope) error {
		if err := bindLifecycle(ctx, sc); err != nil {
			return err
		}
		scope := stored.value.scope
		return sc.Q.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM flow_conversation_messages
 WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid AND parent_message_id=$4::uuid AND parent_revision=$5)`, scope.TenantID, scope.OwnerID, scope.ConversationID, scope.MessageID, int64(scope.Revision)).Scan(&leaf)
	})
	return leaf, journalError(ctx, err)
}
