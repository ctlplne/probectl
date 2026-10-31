// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"errors"
	"math"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type epochLock uint8

const (
	epochRead epochLock = iota
	epochShare
	epochUpdate
)

type conversationEpoch struct {
	generation      uint64
	invalidating    bool
	operation, kind *string
	binding         []byte
}

// Fixed internal lock modes only; no caller SQL. The durable invalidating flag
// is independent of an advisory transaction and the immutable message AAD epoch.
func readConversationEpoch(ctx context.Context, sc tenancy.Scope, lock epochLock) (conversationEpoch, error) {
	query := `SELECT generation,invalidating,operation_id::text,operation_kind,operation_binding FROM flow_conversation_epochs WHERE tenant_id=$1::uuid`
	switch lock {
	case epochRead:
	case epochShare:
		query += ` FOR SHARE`
	case epochUpdate:
		query += ` FOR UPDATE`
	default:
		return conversationEpoch{}, ErrMessageIntegrity
	}
	var result conversationEpoch
	err := sc.Q.QueryRow(ctx, query, sc.Tenant.String()).Scan(&result.generation, &result.invalidating, &result.operation, &result.kind, &result.binding)
	if errors.Is(err, pgx.ErrNoRows) && lock != epochUpdate {
		return conversationEpoch{generation: 1}, nil
	}
	if err != nil {
		return conversationEpoch{}, err
	}
	if result.generation == 0 || result.generation > math.MaxInt64 {
		return conversationEpoch{}, ErrMessageIntegrity
	}
	if result.invalidating {
		if result.operation == nil || result.kind == nil || !validMaintenanceRequest(MaintenanceRequest{ID: *result.operation, Kind: MaintenanceKind(*result.kind), Binding: bindingArray(result.binding)}) || len(result.binding) != 32 {
			return conversationEpoch{}, ErrMessageIntegrity
		}
	} else if result.operation != nil || result.kind != nil || result.binding != nil {
		return conversationEpoch{}, ErrMessageIntegrity
	}
	return result, nil
}

func activeConversationEpoch(ctx context.Context, sc tenancy.Scope, lock epochLock) (uint64, error) {
	state, err := readConversationEpoch(ctx, sc, lock)
	if err != nil {
		return 0, err
	}
	if state.invalidating {
		return 0, ErrJournalGeneration
	}
	return state.generation, nil
}

func bindingArray(value []byte) (binding [32]byte) { copy(binding[:], value); return binding }
