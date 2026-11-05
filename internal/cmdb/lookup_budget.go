// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ErrLookupBudget refuses an incomplete lookup without returning earlier pages.
var ErrLookupBudget = errors.New("cmdb: complete lookup exceeds operation admission")

// LookupPolicy is deployment-owned capacity, never source or caller authority.
// Admission is cumulative over pages, related CIs and selected subject facts.
type LookupPolicy struct {
	Timeout       time.Duration
	ResponseBytes int64
	MemoryBytes   int64
}

// DefaultLookupPolicy supplies starting admission; operators may raise it.
func DefaultLookupPolicy() LookupPolicy {
	return LookupPolicy{Timeout: 15 * time.Second, ResponseBytes: 4 << 20, MemoryBytes: 512 << 20}
}

func lookupPolicy(profiles []LookupPolicy) (LookupPolicy, error) {
	policy := DefaultLookupPolicy()
	if len(profiles) > 1 {
		return policy, ErrLookupBudget
	}
	if len(profiles) == 1 {
		policy = profiles[0]
	}
	if policy.Timeout <= 0 || policy.ResponseBytes <= 0 || policy.MemoryBytes <= 0 {
		return policy, ErrLookupBudget
	}
	return policy, nil
}

type lookupWorkKey struct{}
type lookupWork struct {
	mu               sync.Mutex
	owner            any
	response, memory int64
}

func beginLookup(ctx context.Context, owner any, policy LookupPolicy, policyErr error) (context.Context, context.CancelFunc, error) {
	if policyErr != nil {
		return ctx, nil, policyErr
	}
	if existing, ok := ctx.Value(lookupWorkKey{}).(*lookupWork); ok && existing.owner == owner {
		return ctx, func() {}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, policy.Timeout)
	return context.WithValue(ctx, lookupWorkKey{}, &lookupWork{owner: owner, response: policy.ResponseBytes, memory: policy.MemoryBytes}), cancel, nil
}

func lookupMemory(ctx context.Context, owner any, bytes int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	work, ok := ctx.Value(lookupWorkKey{}).(*lookupWork)
	if !ok || work.owner != owner {
		return ErrLookupBudget
	}
	work.mu.Lock()
	defer work.mu.Unlock()
	if bytes < 0 || bytes > work.memory {
		return ErrLookupBudget
	}
	work.memory -= bytes
	return nil
}

func readLookupBody(ctx context.Context, owner any, body io.Reader) ([]byte, error) {
	work, ok := ctx.Value(lookupWorkKey{}).(*lookupWork)
	if !ok || work.owner != owner {
		return nil, ErrLookupBudget
	}
	work.mu.Lock()
	defer work.mu.Unlock()
	// Covers strict token validation, typed decoding, strings, transient copies
	// and retained page data conservatively, without allocating this allowance.
	limit := min(work.response, work.memory/64)
	if limit <= 0 {
		return nil, ErrLookupBudget
	}
	value, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > limit {
		return nil, fmt.Errorf("%w: response bytes exceed remaining admission=%d", ErrLookupBudget, limit)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	work.memory -= int64(len(value)) * 64
	work.response -= int64(len(value))
	return value, nil
}
