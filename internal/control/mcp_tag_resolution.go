// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
)

func tagReadOptions(pool *pgxpool.Pool, loader mcp.PolicyLoader, src AISources, gate *fairness.Gate) []mcp.Option {
	backend := tagReadBackend(pool, loader, src, gate)
	return []mcp.Option{mcp.WithTagBackend(backend), mcp.WithTagSubjectBackend(backend), mcp.WithTestTagBackend(backend)}
}

func (b mcpTagBackend) TestTagAdmission(ctx context.Context, p *auth.Principal) (func(), error) {
	if p == nil || p.TenantID == "" {
		return nil, apierror.Unauthorized("tenant identity required for test tags")
	}
	if b.fairnessGate == nil {
		return func() {}, nil
	}
	return b.fairnessGate.BeginQuery(ctx, p.TenantID)
}

func (b mcpTagBackend) TestTagContext(ctx context.Context, p *auth.Principal, input tags.TestContextInput) (tags.TestContextResolution, error) {
	if p == nil || p.TenantID == "" {
		return tags.TestContextResolution{}, apierror.Unauthorized("tenant identity required for test tags")
	}
	checker := mcpEntityBackend{pool: b.pool, policyLoader: b.policyLoader}
	policies, err := checker.entitySourcePolicies(ctx, p)
	if err != nil {
		return tags.TestContextResolution{}, err
	}
	return resolveTestTagContext(ctx, p, b.pool, b.flowStore, input,
		func(_ context.Context, principal *auth.Principal, permission string, resource map[string]string) (bool, error) {
			return mcp.ResourceAllowed(principal, permission, policies, resource), nil
		})
}

func tagReadBackend(pool *pgxpool.Pool, loader mcp.PolicyLoader, src AISources, gate *fairness.Gate) mcpTagBackend {
	backend := mcpTagBackend{pool: pool, policyLoader: loader, flowStore: src.Flow, fairnessGate: gate}
	if src.NativeFlow != nil {
		backend.flowStore = src.NativeFlow.flowStore
	}
	return backend
}

func (b mcpTagBackend) TagSubjectResolve(ctx context.Context, p *auth.Principal, input mcp.TagSubjectInput) (tags.SubjectResolution, error) {
	ctx, contextID, err := b.tagContext(ctx, p, input.ContextID)
	if err != nil {
		return tags.SubjectResolution{}, err
	}
	permission, err := tagSubjectReadPermission(input.TargetKind)
	if err != nil {
		return tags.SubjectResolution{}, err
	}
	checker := mcpEntityBackend{pool: b.pool, policyLoader: b.policyLoader}
	if err := checker.requireEntityContext(ctx, p, entity.Scope{TenantID: p.TenantID, ContextID: contextID}, permission); err != nil {
		return tags.SubjectResolution{}, err
	}
	return resolveSubjectTags(ctx, b.pool, b.flowStore, b.fairnessGate,
		tags.Scope{TenantID: p.TenantID, ContextID: contextID}, store.TagSubjectReference{
			Kind: input.TargetKind, ID: input.TargetID,
			ExporterAgentID: input.ExporterAgentID, ExporterSourceRef: input.ExporterSourceRef})
}
