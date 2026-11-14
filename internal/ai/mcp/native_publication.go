// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"errors"
	"sync"
)

type nativePublicationKey struct{}

type nativePublication struct {
	mu       sync.Mutex
	closed   bool
	checks   []func(context.Context) error
	releases []func()
}

func withNativePublication(ctx context.Context) (context.Context, *nativePublication) {
	state := &nativePublication{}
	return context.WithValue(ctx, nativePublicationKey{}, state), state
}

// RetainNativePublication keeps a shared reader's finite admission and source
// snapshot alive through redaction and framing. The source check runs after
// redaction and before the exact transport credential/policy refresh. Only the
// server's per-call context can accept a registration; it is never connection
// state or a caller-controlled tenant/credential substitute.
func RetainNativePublication(ctx context.Context, check func(context.Context) error, release func()) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	state, ok := ctx.Value(nativePublicationKey{}).(*nativePublication)
	if !ok || check == nil || release == nil {
		return errors.New("mcp: native publication scope unavailable")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return errors.New("mcp: native publication scope is closed")
	}
	state.checks = append(state.checks, check)
	state.releases = append(state.releases, release)
	return nil
}

func checkNativePublication(ctx context.Context) error {
	state, ok := ctx.Value(nativePublicationKey{}).(*nativePublication)
	if !ok {
		return ctx.Err()
	}
	state.mu.Lock()
	checks, closed := append([]func(context.Context) error(nil), state.checks...), state.closed
	state.mu.Unlock()
	if closed {
		return errors.New("mcp: native publication scope is closed")
	}
	for _, check := range checks {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := check(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (state *nativePublication) release() {
	state.mu.Lock()
	if state.closed {
		state.mu.Unlock()
		return
	}
	state.closed = true
	releases := state.releases
	state.checks, state.releases = nil, nil
	state.mu.Unlock()
	for i := len(releases) - 1; i >= 0; i-- {
		releases[i]()
	}
}

func (response *rpcResponse) addFinalizer(finalize func()) {
	if finalize == nil {
		return
	}
	previous := response.finalize
	response.finalize = func() {
		defer finalize()
		if previous != nil {
			previous()
		}
	}
}
