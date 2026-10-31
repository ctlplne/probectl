// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// WithSubjectExport selects complete retained descendant closure for a subject.
// match receives authenticated document bytes only after independent fresh
// privacy authority; its result is a selector, never an authorization grant.
// The body is borrowed for this call and is cleared after use. Matching omits
// private metadata/control fields. No total chain, turn or history cap applies.
func (j *Journal) WithSubjectExport(ctx context.Context, budget HistoryBudget, authorize AuthorizeMaintenance, recordAuthority func(context.Context, MessageScope, InputMetadata) error, match func(context.Context, StoredMessage, []byte) (bool, error), fn func(context.Context, func(io.Writer) (int64, error)) error) (bool, error) {
	if match == nil {
		return false, ErrMessageDenied
	}
	return j.withTenantExport(ctx, budget, authorize, recordAuthority, match, fn)
}

func (j *Journal) selectExportMessage(ctx context.Context, codec *Codec, stored StoredMessage, bounds InputMetadata, body []byte, check func(context.Context) error, authorize func(context.Context, MessageScope, InputMetadata) error, match func(context.Context, StoredMessage, []byte) (bool, error), remaining *int) (bool, error) {
	if match == nil {
		return true, nil
	}
	selected, err := match(ctx, stored, body)
	if err != nil {
		return false, err
	}
	child := stored
	for child.value.meta.Parent != nil {
		if err := check(ctx); err != nil {
			return false, err
		}
		if remaining == nil || *remaining <= 0 {
			return false, ErrMessageBudget
		}
		parent, err := j.exportAncestor(ctx, child, *remaining)
		if err != nil {
			return false, err
		}
		*remaining -= parent.StoredBytes()
		ancestorSelected, err := matchExportAncestor(ctx, codec, parent, bounds, check, authorize, match)
		if err != nil {
			return false, err
		}
		selected = selected || ancestorSelected
		child = parent
	}
	return selected, check(ctx)
}

func matchExportAncestor(ctx context.Context, codec *Codec, parent StoredMessage, bounds InputMetadata, check func(context.Context) error, authorize func(context.Context, MessageScope, InputMetadata) error, match func(context.Context, StoredMessage, []byte) (bool, error)) (bool, error) {
	current := func(ctx context.Context, scope MessageScope, _ auth.WorkerCredentialRef, _ []string) error {
		if scope != parent.value.scope || !parent.value.meta.ExpiresAt.IsZero() && !parent.value.meta.ExpiresAt.After(time.Now()) || !bounds.ExpiresAt.IsZero() && !bounds.ExpiresAt.After(time.Now()) {
			return ErrMessageIntegrity
		}
		if err := check(ctx); err != nil {
			return err
		}
		return authorize(ctx, scope, bounds)
	}
	body, err := codec.Open(ctx, parent.value.scope, parent.value.sealed, current)
	if err != nil {
		return false, err
	}
	defer clear(body)
	selected, err := match(ctx, parent, body)
	if err != nil {
		return false, err
	}
	return selected, check(ctx)
}

// Exact immutable parent read, with the same tenant/owner/conversation scope.
// Positive decreasing positions bound traversal without a visited-set heap cap.
func (j *Journal) exportAncestor(ctx context.Context, child StoredMessage, bytes int) (StoredMessage, error) {
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
		parent, _, err = scanStoredMessage(ctx, sc.Q.QueryRow(ctx, `SELECT `+historyColumns+` FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid AND message_id=$4::uuid AND revision=$5 AND `+historyRetained, value.scope.TenantID, value.scope.OwnerID, value.scope.ConversationID, value.meta.Parent.MessageID, int64(value.meta.Parent.Revision), bytes), historyIdentity{tenant: value.scope.TenantID, owner: value.scope.OwnerID}, value.scope.ConversationID, bytes)
		return err
	})
	if err != nil {
		return StoredMessage{}, journalError(ctx, err)
	}
	if parent.value.position >= value.position || parent.value.scope.Epoch > value.scope.Epoch || parent.value.meta.FrozenAt.After(value.meta.FrozenAt) {
		return StoredMessage{}, ErrMessageIntegrity
	}
	return parent, nil
}
