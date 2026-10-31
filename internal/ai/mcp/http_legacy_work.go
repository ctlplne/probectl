// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
)

type legacyHTTPScope struct{ tenant, user, credential string }
type legacyHTTPKey struct {
	scope legacyHTTPScope
	id    string
}
type legacyHTTPRegistry struct {
	mu     sync.Mutex
	active map[legacyHTTPKey]*legacyHTTPJob
	tokens map[legacyHTTPKey]*legacyHTTPJob
}
type legacyHTTPJob struct {
	registry *legacyHTTPRegistry
	key      legacyHTTPKey
	method   string
	ctx      context.Context
	cancel   context.CancelFunc
	tokenKey legacyHTTPKey
}

func legacyCredentialHash(bearer string) string { return string(crypto.Hash([]byte(bearer))) }

func legacyScope(p *auth.Principal, bearer string) legacyHTTPScope {
	return legacyHTTPScope{tenant: p.TenantID, user: p.UserID, credential: legacyCredentialHash(bearer)}
}

func (r *legacyHTTPRegistry) begin(ctx context.Context, p *auth.Principal, bearer string, req rpcRequest, budget HTTPWorkBudget) (*legacyHTTPJob, *rpcResponse) {
	if budget.Validate() != nil {
		return nil, errorResponse(req.ID, codeUnavailable, "HTTP work policy is unavailable")
	}
	id, valid := requestIDKey(req.ID)
	if !valid {
		return nil, errorResponse(nil, codeInvalidRequest, "invalid request id")
	}
	deadline := time.Now().Add(budget.Timeout)
	if bound, ok := ctx.Deadline(); ok && bound.Before(deadline) {
		deadline = bound
	}
	workCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	job := &legacyHTTPJob{registry: r, key: legacyHTTPKey{scope: legacyScope(p, bearer), id: id}, method: req.Method, ctx: workCtx, cancel: cancel}
	if token, valid := requestIDKey(req.protocol.progress); valid {
		job.tokenKey = legacyHTTPKey{scope: job.key.scope, id: token}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active[job.key] != nil {
		cancel()
		return nil, errorResponse(nil, codeInvalidRequest, "request id is already active")
	}
	if job.tokenKey.id != "" && r.tokens[job.tokenKey] != nil {
		cancel()
		return nil, errorResponse(req.ID, codeInvalidRequest, "progress token is already active")
	}
	if len(r.active) >= budget.ActiveRequests {
		cancel()
		return nil, errorResponse(req.ID, codeRateLimited, "HTTP active request budget is full")
	}
	r.active[job.key] = job
	if job.tokenKey.id != "" {
		if r.tokens == nil {
			r.tokens = map[legacyHTTPKey]*legacyHTTPJob{}
		}
		r.tokens[job.tokenKey] = job
	}
	return job, nil
}

func (r *legacyHTTPRegistry) cancelRequest(p *auth.Principal, bearer, id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if job := r.active[legacyHTTPKey{scope: legacyScope(p, bearer), id: id}]; job != nil && job.method != "initialize" {
		job.cancel()
	}
}

// A now-invalid credential may cancel its own previously admitted work. It
// cannot acquire data or cancel another credential, tenant or user's work.
func (r *legacyHTTPRegistry) cancelCredential(bearer string) {
	credential := legacyCredentialHash(bearer)
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, job := range r.active {
		if key.scope.credential == credential {
			job.cancel()
		}
	}
}

func (j *legacyHTTPJob) finish() {
	j.cancel()
	j.registry.mu.Lock()
	defer j.registry.mu.Unlock()
	if j.registry.active[j.key] == j {
		delete(j.registry.active, j.key)
	}
	if j.tokenKey.id != "" && j.registry.tokens[j.tokenKey] == j {
		delete(j.registry.tokens, j.tokenKey)
	}
}

func (j *legacyHTTPJob) commit(final bool) bool {
	j.registry.mu.Lock()
	defer j.registry.mu.Unlock()
	if j.ctx.Err() != nil {
		return false
	}
	if final && j.registry.active[j.key] == j {
		delete(j.registry.active, j.key)
	}
	if final && j.tokenKey.id != "" && j.registry.tokens[j.tokenKey] == j {
		delete(j.registry.tokens, j.tokenKey)
	}
	return true
}
