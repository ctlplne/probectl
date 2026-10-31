// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Fold complete immutable ancestry metadata before source. Strictly decreasing
// positive positions prevent cycles without a total history/turn cap or an
// unbounded in-memory visited set. No ancestor payload or credential is read.
func (j *Journal) exportHistoryBounds(ctx context.Context, stored StoredMessage) (InputMetadata, error) {
	message := stored.value
	bounds := InputMetadata{FrozenAt: message.meta.FrozenAt, ExpiresAt: message.meta.ExpiresAt}
	parent, position := message.meta.Parent, message.position
	for parent != nil {
		if err := ctx.Err(); err != nil {
			return InputMetadata{}, err
		}
		if !validWorkInput(message.scope.ConversationID, *parent) {
			return InputMetadata{}, ErrMessageIntegrity
		}
		var frozen string
		var expires *time.Time
		var next *string
		var nextRevision *int64
		var parentPosition, parentEpoch int64
		err := j.scoped(ctx, func(ctx context.Context, scope tenancy.Scope) error {
			if scope.Tenant.String() != message.scope.TenantID {
				return ErrMessageDenied
			}
			if err := bindLifecycle(ctx, scope); err != nil {
				return err
			}
			return scope.Q.QueryRow(ctx, `SELECT frozen_at,expires_at,parent_message_id::text,parent_revision,position,epoch FROM flow_conversation_messages
 WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid AND message_id=$4::uuid AND revision=$5`,
				message.scope.TenantID, message.scope.OwnerID, message.scope.ConversationID, parent.MessageID, int64(parent.Revision)).Scan(&frozen, &expires, &next, &nextRevision, &parentPosition, &parentEpoch)
		})
		if err != nil {
			return InputMetadata{}, journalError(ctx, err)
		}
		at, err := time.Parse(time.RFC3339Nano, frozen)
		if err != nil || at.UTC().Format(time.RFC3339Nano) != frozen || at.After(message.meta.FrozenAt) || parentPosition <= 0 || uint64(parentPosition) >= position || parentEpoch <= 0 || uint64(parentEpoch) > message.scope.Epoch || (next == nil) != (nextRevision == nil) {
			return InputMetadata{}, ErrMessageIntegrity
		}
		if at.Before(bounds.FrozenAt) {
			bounds.FrozenAt = at
		}
		if expires != nil {
			if !expires.After(at) {
				return InputMetadata{}, ErrMessageIntegrity
			}
			if bounds.ExpiresAt.IsZero() || expires.Before(bounds.ExpiresAt) {
				bounds.ExpiresAt = *expires
			}
		}
		position, parent = uint64(parentPosition), nil
		if next != nil {
			if *nextRevision <= 0 {
				return InputMetadata{}, ErrMessageIntegrity
			}
			parent = &Revision{MessageID: *next, Revision: uint64(*nextRevision)}
		}
	}
	return bounds, nil
}
