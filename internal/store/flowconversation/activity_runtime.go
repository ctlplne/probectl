// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"sort"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
)

// Shared only by Journals on this process's exact pool. No source, creator
// credential, permission snapshot or original context may enter this state.
var activityRuntimes sync.Map

type activityRuntime struct {
	mu           sync.Mutex
	instance     string
	pendingLimit int
	refs         map[string]map[string]*activityRef
}
type activityRef struct {
	runtime                            *activityRuntime
	tenant, owner, operation, instance string
	generation                         uint64
	attempted, drained, retiring       bool
}

func activityRuntimeFor(pool *pgxpool.Pool) (*activityRuntime, error) {
	if pool == nil || pool.Config().MaxConns < 4 {
		return nil, ErrJournalUnavailable
	}
	if value, ok := activityRuntimes.Load(pool); ok {
		return value.(*activityRuntime), nil
	}
	instance, err := crypto.UUIDv4()
	if err != nil {
		return nil, ErrJournalUnavailable
	}
	state := &activityRuntime{instance: instance, pendingLimit: max(1, (int(pool.Config().MaxConns)-1)/3), refs: make(map[string]map[string]*activityRef)}
	value, _ := activityRuntimes.LoadOrStore(pool, state)
	return value.(*activityRuntime), nil
}
func (state *activityRuntime) reserve(ctx context.Context, tenant, owner string) (*activityRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	operation, err := crypto.UUIDv4()
	if err != nil {
		return nil, ErrJournalUnavailable
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	pending := 0
	for _, ref := range state.refs[tenant] {
		if ref.drained {
			pending++
		}
	}
	if pending >= state.pendingLimit {
		return nil, ErrJournalUnavailable
	}
	if state.refs[tenant] == nil {
		state.refs[tenant] = make(map[string]*activityRef)
	}
	ref := &activityRef{runtime: state, tenant: tenant, owner: owner, operation: operation, instance: state.instance}
	state.refs[tenant][operation] = ref
	return ref, nil
}
func (state *activityRuntime) owned(ref *activityRef) bool {
	return ref != nil && ref.runtime == state && state.refs[ref.tenant][ref.operation] == ref && ref.instance == state.instance
}
func (state *activityRuntime) setAttempt(ref *activityRef, generation uint64) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.owned(ref) || ref.drained {
		return ErrMessageDenied
	}
	ref.generation, ref.attempted = generation, true
	return nil
}
func (state *activityRuntime) isActive(ref *activityRef) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.owned(ref) && ref.attempted && !ref.drained && ref.generation > 0
}
func (state *activityRuntime) drainAndClaim(ref *activityRef) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.owned(ref) {
		return false
	}
	ref.drained = true
	ref.retiring = true
	return true
}
func (state *activityRuntime) claimRetry(ref *activityRef) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.owned(ref) || !ref.drained || ref.retiring {
		return false
	}
	ref.retiring = true
	return true
}
func (state *activityRuntime) canRetire(ref *activityRef) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.owned(ref) && ref.drained && ref.retiring && ref.attempted && ref.generation > 0
}
func (state *activityRuntime) finishRetirement(ref *activityRef, err error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.owned(ref) {
		return
	}
	if err != nil {
		ref.retiring = false
		return
	}
	delete(state.refs[ref.tenant], ref.operation)
	if len(state.refs[ref.tenant]) == 0 {
		delete(state.refs, ref.tenant)
	}
}
func (state *activityRuntime) abandonUnstarted(ref *activityRef) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.owned(ref) || ref.attempted {
		return
	}
	delete(state.refs[ref.tenant], ref.operation)
	if len(state.refs[ref.tenant]) == 0 {
		delete(state.refs, ref.tenant)
	}
}
func (state *activityRuntime) retries(tenant string, limit int) ([]*activityRef, int) {
	state.mu.Lock()
	defer state.mu.Unlock()
	var keys []string
	for id, ref := range state.refs[tenant] {
		if ref.drained {
			keys = append(keys, id)
		}
	}
	sort.Strings(keys)
	total := len(keys)
	result := make([]*activityRef, 0, min(limit, total))
	for _, id := range keys {
		if len(result) == limit {
			break
		}
		if !state.refs[tenant][id].retiring {
			result = append(result, state.refs[tenant][id])
		}
	}
	return result, total
}
