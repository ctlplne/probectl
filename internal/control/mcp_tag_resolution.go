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
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
)

func tagReadOptions(pool *pgxpool.Pool, loader mcp.PolicyLoader, src AISources, gate *fairness.Gate) []mcp.Option {
	backend := mcpTagBackend{pool: pool, policyLoader: loader, flowStore: src.Flow, fairnessGate: gate}
	if src.NativeFlow != nil {
		backend.flowStore = src.NativeFlow.flowStore
	}
	return []mcp.Option{mcp.WithTagBackend(backend), mcp.WithTagSubjectBackend(backend)}
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
