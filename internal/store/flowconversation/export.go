// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// WithTenantExport holds independent current privacy authority and durable
// actual-drain registration through the complete archive/output callback.
// Installed=false means no history family exists; partial/unknown families
// refuse. The callback receives a single-use streaming function, not data or
// authority that may outlive this operation. Historical origins grant nothing.
func (j *Journal) WithTenantExport(ctx context.Context, budget HistoryBudget, authorize AuthorizeMaintenance, recordAuthority func(context.Context, MessageScope, InputMetadata) error, fn func(context.Context, func(io.Writer) (int64, error)) error) (bool, error) {
	if _, err := maintenanceTenant(ctx); err != nil {
		return false, err
	}
	if budget.Rows <= 0 || budget.Bytes <= 0 || fn == nil {
		return false, ErrMessageBudget
	}
	installed, err := j.historyFamilyInstalled(ctx)
	if err != nil || !installed {
		return installed, err
	}
	if authorize == nil || recordAuthority == nil {
		return true, ErrMessageDenied
	}
	codec, err := NewCodec(DefaultCodecBudget())
	if err != nil {
		return true, err
	}
	err = j.withTenantExportSource(ctx, authorize, func(ctx context.Context, check func(context.Context) error) error {
		var used atomic.Bool
		var mu sync.Mutex
		var finished bool
		var streamErr error
		stream := func(w io.Writer) (count int64, result error) {
			if !used.CompareAndSwap(false, true) {
				return 0, ErrMessageDenied
			}
			defer func() { mu.Lock(); finished, streamErr = true, result; mu.Unlock() }()
			lease, ok := ctx.Value(tenantExportLeaseKey{}).(*operationLease)
			if !ok || w == nil || j.exportLeaseScope(ctx, lease) != nil || !lease.enter() {
				return 0, ErrMessageDenied
			}
			defer lease.readers.Done()
			return j.streamTenantHistory(ctx, codec, budget, check, recordAuthority, w)
		}
		if err := fn(ctx, stream); err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if !finished {
			return ErrMessageDenied
		}
		return streamErr
	})
	return true, err
}

type portableHistoryParent struct {
	MessageID string `json:"message_id"`
	Revision  uint64 `json:"revision"`
}
type portableHistoryMessage struct {
	TenantID       string                 `json:"tenant_id"`
	OwnerID        string                 `json:"owner_id"`
	ConversationID string                 `json:"conversation_id"`
	MessageID      string                 `json:"message_id"`
	Revision       uint64                 `json:"revision"`
	Position       uint64                 `json:"position"`
	Parent         *portableHistoryParent `json:"parent,omitempty"`
	Kind           string                 `json:"kind"`
	FrozenAt       time.Time              `json:"frozen_at"`
	ExpiresAt      *time.Time             `json:"expires_at,omitempty"`
	Document       json.RawMessage        `json:"document"`
}

type exportPosition struct {
	owner, conversation, message string
	revision                     uint64
}

func (j *Journal) streamTenantHistory(ctx context.Context, codec *Codec, budget HistoryBudget, check func(context.Context) error, authorize func(context.Context, MessageScope, InputMetadata) error, w io.Writer) (int64, error) {
	var after exportPosition
	var total int64
	for {
		if err := check(ctx); err != nil {
			return 0, err
		}
		last, rows, err := j.exportHistoryPage(ctx, codec, after, budget, check, authorize, w)
		if err != nil {
			return 0, err
		}
		if rows > math.MaxInt64-total {
			return 0, ErrMessageBudget
		}
		total += rows
		if rows == 0 {
			return total, check(ctx)
		}
		after = last
	}
}

func (j *Journal) exportHistoryPage(ctx context.Context, codec *Codec, after exportPosition, budget HistoryBudget, check func(context.Context) error, authorize func(context.Context, MessageScope, InputMetadata) error, w io.Writer) (exportPosition, int64, error) {
	last := after
	var count int64
	err := j.scoped(ctx, func(ctx context.Context, scope tenancy.Scope) error {
		if err := bindLifecycle(ctx, scope); err != nil {
			return err
		}
		columns := historyColumnsBase + `,
 CASE WHEN sum(` + historyStoredBytes + `) OVER(ORDER BY owner_id,conversation_id,message_id,revision)<=$7 THEN private_header END,
 CASE WHEN sum(` + historyStoredBytes + `) OVER(ORDER BY owner_id,conversation_id,message_id,revision)<=$7 THEN private_payload END`
		var owner, conversation, message any
		if after.owner != "" {
			owner, conversation, message = after.owner, after.conversation, after.message
		}
		rows, err := scope.Q.Query(ctx, `SELECT `+columns+` FROM (SELECT * FROM flow_conversation_messages
 WHERE tenant_id=$1::uuid AND ($2::uuid IS NULL OR (owner_id,conversation_id,message_id,revision)>($2::uuid,$3::uuid,$4::uuid,$5))
 AND `+historyRetained+` ORDER BY owner_id,conversation_id,message_id,revision LIMIT $6) AS portable_candidates
 ORDER BY owner_id,conversation_id,message_id,revision`, scope.Tenant.String(), owner, conversation, message, int64(after.revision), budget.Rows, budget.Bytes)
		if err != nil {
			return err
		}
		defer rows.Close()
		used := 0
		for rows.Next() {
			stored, size, err := scanTenantMessage(ctx, rows, budget.Bytes-used)
			if err != nil {
				return err
			}
			used += size
			position := exportPosition{stored.value.scope.OwnerID, stored.value.scope.ConversationID, stored.value.scope.MessageID, stored.value.scope.Revision}
			if count >= int64(budget.Rows) || !exportPositionAfter(position, last) {
				return ErrMessageIntegrity
			}
			bounds, err := j.exportHistoryBounds(ctx, stored)
			if err != nil {
				return err
			}
			if err := exportPortableMessage(ctx, codec, stored, bounds, check, authorize, w); err != nil {
				return err
			}
			last, count = position, count+1
		}
		return rows.Err()
	})
	return last, count, journalError(ctx, err)
}

func exportPositionAfter(next, previous exportPosition) bool {
	if next.owner != previous.owner {
		return next.owner > previous.owner
	}
	if next.conversation != previous.conversation {
		return next.conversation > previous.conversation
	}
	if next.message != previous.message {
		return next.message > previous.message
	}
	return next.revision > previous.revision
}

func exportPortableMessage(ctx context.Context, codec *Codec, stored StoredMessage, bounds InputMetadata, check func(context.Context) error, authorize func(context.Context, MessageScope, InputMetadata) error, w io.Writer) error {
	message := stored.value
	if err := check(ctx); err != nil {
		return err
	}
	authorizeCurrent := func(ctx context.Context, scope MessageScope, _ auth.WorkerCredentialRef, _ []string) error {
		if scope != message.scope || !message.meta.ExpiresAt.IsZero() && !message.meta.ExpiresAt.After(time.Now()) {
			return ErrMessageDenied
		}
		if err := check(ctx); err != nil {
			return err
		}
		return authorize(ctx, scope, bounds)
	}
	body, err := codec.Open(ctx, message.scope, message.sealed, authorizeCurrent)
	if err != nil {
		return err
	}
	defer clear(body)
	portable := portableHistoryMessage{TenantID: message.scope.TenantID, OwnerID: message.scope.OwnerID,
		ConversationID: message.scope.ConversationID, MessageID: message.scope.MessageID, Revision: message.scope.Revision,
		Position: message.position, Kind: message.kind, FrozenAt: message.meta.FrozenAt, Document: body}
	if message.meta.Parent != nil {
		portable.Parent = &portableHistoryParent{message.meta.Parent.MessageID, message.meta.Parent.Revision}
	}
	if !message.meta.ExpiresAt.IsZero() {
		portable.ExpiresAt = &message.meta.ExpiresAt
	}
	encoded, err := json.Marshal(portable)
	if err != nil {
		return err
	}
	defer clear(encoded)
	if err := authorizeCurrent(ctx, message.scope, auth.WorkerCredentialRef{}, nil); err != nil {
		return err
	}
	if n, err := w.Write(encoded); err != nil {
		return err
	} else if n != len(encoded) {
		return io.ErrShortWrite
	}
	if n, err := io.WriteString(w, "\n"); err != nil {
		return err
	} else if n != 1 {
		return io.ErrShortWrite
	}
	return check(ctx)
}
