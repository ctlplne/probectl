// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var _ mcp.EntityBackend = mcpEntityBackend{}

type mcpEntityBackend struct {
	pool         *pgxpool.Pool
	pathStore    pathstore.Store
	policyLoader mcp.PolicyLoader
}

func (b mcpEntityBackend) EntityContextList(ctx context.Context, p *auth.Principal, input mcp.EntityContextListInput) (mcp.EntityContextListResult, error) {
	if p == nil || p.TenantID == "" {
		return mcp.EntityContextListResult{}, apierror.Forbidden("tenant identity is required")
	}
	if input.Limit == 0 {
		input.Limit = 50
	}
	page, err := store.NewEntityRegistry(b.pool).ListEntityContexts(
		tenancy.WithTenant(ctx, tenancy.ID(p.TenantID)), input.Cursor, input.Limit)
	if err != nil {
		return mcp.EntityContextListResult{}, entityAPIError(err)
	}
	policies, err := b.entitySourcePolicies(ctx, p)
	if err != nil {
		return mcp.EntityContextListResult{}, err
	}
	out := mcp.EntityContextListResult{Items: make([]mcp.EntityContextResult, 0, len(page.Items)),
		NextCursor: page.NextCursor}
	for _, item := range page.Items {
		resource := entityContextResource(item)
		if !mcp.ResourceAllowed(p, "entities.read", policies, resource) {
			return mcp.EntityContextListResult{}, apierror.Forbidden("entity routing context is not authorized")
		}
		out.Items = append(out.Items, mcp.EntityContextResult{ContextID: item.ContextID,
			SiteID: item.SiteID, VRFID: item.VRFID,
			SiteLabel: item.SiteLabel, VRFLabel: item.VRFLabel})
	}
	return out, nil
}

func (b mcpEntityBackend) EntityContextCreate(ctx context.Context, p *auth.Principal, input mcp.EntityContextCreateInput) (mcp.EntityContextResult, error) {
	if p == nil || p.TenantID == "" {
		return mcp.EntityContextResult{}, apierror.Forbidden("tenant identity is required")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(p.TenantID))
	attributes, err := store.EntityContextAttributes(p.TenantID, input.SiteLabel, input.VRFLabel)
	if err != nil {
		return mcp.EntityContextResult{}, entityAdminError(err)
	}
	policies, err := b.entitySourcePolicies(ctx, p)
	if err != nil {
		return mcp.EntityContextResult{}, err
	}
	if !mcp.ResourceAllowed(p, "agent.write", policies, entityContextResource(attributes)) {
		return mcp.EntityContextResult{}, apierror.Forbidden("entity context creation is not authorized")
	}
	var out mcp.EntityContextResult
	if err := tenancy.InTenant(ctx, b.pool, func(ctx context.Context, sc tenancy.Scope) error {
		scope, err := store.NewEntityRegistry(b.pool).CreateEntityContext(ctx, sc,
			input.SiteLabel, input.VRFLabel)
		if err != nil {
			return err
		}
		out = mcp.EntityContextResult{ContextID: scope.ContextID,
			SiteID: scope.SiteID, VRFID: scope.VRFID,
			SiteLabel: scope.SiteLabel, VRFLabel: scope.VRFLabel}
		_, err = audit.TenantAppend(ctx, sc, p.UserID, "entity.context.created", scope.ContextID,
			map[string]any{"site_id": scope.SiteID, "vrf_id": scope.VRFID,
				"site_label": scope.SiteLabel, "vrf_label": scope.VRFLabel})
		return err
	}); err != nil {
		return mcp.EntityContextResult{}, entityAdminError(err)
	}
	return out, nil
}

func (b mcpEntityBackend) EntityCreate(ctx context.Context, p *auth.Principal, input mcp.EntityCreateInput) (mcp.EntityItemResult, error) {
	ctx, scope, err := entityMCPContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.EntityItemResult{}, err
	}
	if err := b.requireEntityContext(ctx, p, scope, "agent.write"); err != nil {
		return mcp.EntityItemResult{}, err
	}
	var record entity.Record
	if err := tenancy.InTenant(ctx, b.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		record, err = store.NewEntityRegistry(b.pool).CreateCanonicalEntity(ctx, sc,
			scope.ContextID, entity.Kind(input.Kind), input.Label)
		if err != nil {
			return err
		}
		_, err = audit.TenantAppend(ctx, sc, p.UserID, "entity.created", record.ID,
			map[string]any{"context_id": scope.ContextID, "kind": record.Kind})
		return err
	}); err != nil {
		return mcp.EntityItemResult{}, entityAdminError(err)
	}
	return mcpEntityItem(record), nil
}

func entityMCPContext(ctx context.Context, p *auth.Principal, routingContext string) (context.Context, entity.Scope, error) {
	if p == nil || p.TenantID == "" {
		return nil, entity.Scope{}, apierror.Forbidden("tenant identity is required")
	}
	scope, err := (entity.Scope{TenantID: p.TenantID, ContextID: routingContext}).Normalize()
	if err != nil {
		return nil, entity.Scope{}, entityAPIError(err)
	}
	return tenancy.WithTenant(ctx, tenancy.ID(p.TenantID)), scope, nil
}

func mcpEntityItem(record entity.Record) mcp.EntityItemResult {
	return mcp.EntityItemResult{ID: record.ID, ContextID: record.Scope.ContextID,
		Kind: string(record.Kind), Label: record.Label, UpdatedAt: record.UpdatedAt}
}

func (b mcpEntityBackend) EntityList(ctx context.Context, p *auth.Principal, input mcp.EntityListInput) (mcp.EntityListResult, error) {
	ctx, scope, err := entityMCPContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.EntityListResult{}, err
	}
	if input.Limit == 0 {
		input.Limit = 50
	}
	page, err := store.NewEntityRegistry(b.pool).ListEntities(ctx, scope, input.Cursor, input.Limit)
	if err != nil {
		return mcp.EntityListResult{}, entityAPIError(err)
	}
	if err := b.requireEntityContext(ctx, p, scope, "entities.read"); err != nil {
		return mcp.EntityListResult{}, err
	}
	out := mcp.EntityListResult{Items: make([]mcp.EntityItemResult, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, item := range page.Items {
		out.Items = append(out.Items, mcpEntityItem(item))
	}
	return out, nil
}

func (b mcpEntityBackend) EntityGet(ctx context.Context, p *auth.Principal, input mcp.EntityGetInput) (mcp.EntityItemResult, error) {
	ctx, scope, err := entityMCPContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.EntityItemResult{}, err
	}
	record, err := store.NewEntityRegistry(b.pool).GetEntity(ctx, scope, input.ID)
	if err != nil {
		return mcp.EntityItemResult{}, entityAPIError(err)
	}
	if err := b.requireEntityContext(ctx, p, scope, "entities.read"); err != nil {
		return mcp.EntityItemResult{}, err
	}
	return mcpEntityItem(record), nil
}

func (b mcpEntityBackend) entitySourcePolicies(ctx context.Context, p *auth.Principal) ([]auth.Policy, error) {
	if b.policyLoader == nil {
		return nil, apierror.Unavailable("MCP entity policy store is unavailable")
	}
	policies, err := b.policyLoader(ctx, p.TenantID)
	if err != nil {
		return nil, apierror.Unavailable("MCP entity policy store is unavailable")
	}
	return policies, nil
}

func (b mcpEntityBackend) requireEntityContext(ctx context.Context, p *auth.Principal,
	scope entity.Scope, permission string) error {
	policies, err := b.entitySourcePolicies(ctx, p)
	if err != nil {
		return err
	}
	resource, err := b.entityResource(ctx, scope)
	if err != nil {
		return err
	}
	if !mcp.ResourceAllowed(p, permission, policies, resource) {
		return apierror.Forbidden("entity routing context is not authorized")
	}
	return nil
}

func (b mcpEntityBackend) entityResource(ctx context.Context, scope entity.Scope) (map[string]string, error) {
	record, err := store.NewEntityRegistry(b.pool).GetEntityContext(ctx, scope)
	if err != nil {
		return nil, entityAPIError(err)
	}
	return entityContextResource(record), nil
}

func entityMCPSourceAllowed(p *auth.Principal, policies []auth.Policy,
	resource map[string]string, kind entity.SourceKind) bool {
	permission := entitySourcePermission(kind)
	return permission != "" && mcp.ResourceAllowed(p, permission, policies, resource)
}

func entityMCPResolutionAllowed(p *auth.Principal, policies []auth.Policy,
	result entity.Resolution, resource map[string]string) bool {
	if !mcp.ResourceAllowed(p, "entities.read", policies, resource) {
		return false
	}
	for _, candidate := range result.Candidates {
		if !entityMCPSourceAllowed(p, policies, resource, candidate.SourceKey.Kind) ||
			(candidate.SupportEvidenceID != "" &&
				!entityMCPSourceAllowed(p, policies, resource, entity.DeviceTarget)) {
			return false
		}
	}
	if result.MoreCandidates {
		for _, kind := range entityEvidenceSourceKinds {
			if !entityMCPSourceAllowed(p, policies, resource, kind) {
				return false
			}
		}
	}
	return true
}

func (b mcpEntityBackend) EntityEvidenceList(ctx context.Context, p *auth.Principal, input mcp.EntityDetailListInput) (mcp.EntityEvidenceListResult, error) {
	ctx, scope, err := entityMCPContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.EntityEvidenceListResult{}, err
	}
	if input.Limit == 0 {
		input.Limit = 50
	}
	page, err := store.NewEntityRegistry(b.pool).ListEntityEvidence(ctx, scope,
		input.ID, input.Cursor, input.Limit)
	if err != nil {
		return mcp.EntityEvidenceListResult{}, entityAPIError(err)
	}
	policies, err := b.entitySourcePolicies(ctx, p)
	if err != nil {
		return mcp.EntityEvidenceListResult{}, err
	}
	resource, err := b.entityResource(ctx, scope)
	if err != nil {
		return mcp.EntityEvidenceListResult{}, err
	}
	if !mcp.ResourceAllowed(p, "entities.read", policies, resource) {
		return mcp.EntityEvidenceListResult{}, apierror.Forbidden("entity routing context is not authorized")
	}
	out := mcp.EntityEvidenceListResult{EntityID: page.EntityID,
		Items: make([]mcp.EntityEvidenceResult, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, item := range page.Items {
		if !entityMCPSourceAllowed(p, policies, resource, item.SourceKey.Kind) ||
			(item.SupportEvidenceID != "" &&
				!entityMCPSourceAllowed(p, policies, resource, entity.DeviceTarget)) {
			return mcp.EntityEvidenceListResult{}, apierror.Forbidden("entity evidence source is not authorized")
		}
		out.Items = append(out.Items, mcp.EntityEvidenceResult{
			ID: item.ID, ObservationID: item.ObservationID,
			SupportEvidenceID: item.SupportEvidenceID,
			AliasKind:         string(item.Alias.Kind), AliasValue: item.Alias.Value,
			Source: item.Source, SourceRef: item.SourceRef,
			AgentID: item.SourceKey.AgentID, SourceKind: string(item.SourceKey.Kind),
			ConfiguredRef: item.SourceKey.SourceRef, ObservedAt: item.ObservedAt,
			InterfaceName: item.InterfaceName, InterfaceDescription: item.InterfaceDescription,
			NeighborProtocol:     item.NeighborProtocol,
			NeighborLocalIfIndex: item.NeighborLocalIfIndex,
			NeighborLocalPortID:  item.NeighborLocalPortID,
			NeighborRemotePortID: item.NeighborRemotePortID,
			NeighborChassisID:    item.NeighborChassisID,
			NeighborDeviceName:   item.NeighborDeviceName,
			NeighborAddress:      item.NeighborAddress,
			Current:              item.Current,
		})
	}
	return out, nil
}

func (b mcpEntityBackend) EntityLinkList(ctx context.Context, p *auth.Principal, input mcp.EntityDetailListInput) (mcp.EntityLinkListResult, error) {
	ctx, scope, err := entityMCPContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.EntityLinkListResult{}, err
	}
	if input.Limit == 0 {
		input.Limit = 50
	}
	page, err := store.NewEntityRegistry(b.pool).ListEntityLinks(ctx, scope,
		input.ID, input.Cursor, input.Limit)
	if err != nil {
		return mcp.EntityLinkListResult{}, entityAPIError(err)
	}
	policies, err := b.entitySourcePolicies(ctx, p)
	if err != nil {
		return mcp.EntityLinkListResult{}, err
	}
	resource, err := b.entityResource(ctx, scope)
	if err != nil {
		return mcp.EntityLinkListResult{}, err
	}
	if !mcp.ResourceAllowed(p, "entities.read", policies, resource) {
		return mcp.EntityLinkListResult{}, apierror.Forbidden("entity routing context is not authorized")
	}
	out := mcp.EntityLinkListResult{EntityID: page.EntityID,
		Items: make([]mcp.EntityLinkResult, 0, len(page.Items)), NextCursor: page.NextCursor}
	for _, item := range page.Items {
		if !entityMCPSourceAllowed(p, policies, resource, item.SourceKind) {
			return mcp.EntityLinkListResult{}, apierror.Forbidden("entity link source is not authorized")
		}
		out.Items = append(out.Items, mcp.EntityLinkResult{ID: item.ID,
			FromEntityID: item.FromEntityID, ToEntityID: item.ToEntityID,
			EvidenceID: item.EvidenceID, Kind: item.Kind,
			SourceKind: string(item.SourceKind), ObservedAt: item.ObservedAt})
	}
	return out, nil
}

func (b mcpEntityBackend) EntityResolve(ctx context.Context, p *auth.Principal, input mcp.EntityResolveInput) (mcp.EntityResolutionResult, error) {
	ctx, scope, err := entityMCPContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.EntityResolutionResult{}, err
	}
	resolved, err := store.NewEntityRegistry(b.pool).ResolveAlias(ctx, scope,
		entity.AliasKey{Kind: entity.AliasKind(input.Kind), Value: input.Value})
	if err != nil {
		return mcp.EntityResolutionResult{}, entityAPIError(err)
	}
	policies, err := b.entitySourcePolicies(ctx, p)
	if err != nil {
		return mcp.EntityResolutionResult{}, err
	}
	resource, err := b.entityResource(ctx, scope)
	if err != nil {
		return mcp.EntityResolutionResult{}, err
	}
	if !entityMCPResolutionAllowed(p, policies, resolved, resource) {
		return mcp.EntityResolutionResult{}, apierror.Forbidden("entity evidence source is not authorized")
	}
	out := mcp.EntityResolutionResult{ContextID: scope.ContextID, Status: string(resolved.Status),
		EntityID: resolved.EntityID, MoreCandidates: resolved.MoreCandidates,
		Candidates: make([]mcp.EntityCandidateResult, 0, len(resolved.Candidates))}
	for _, candidate := range resolved.Candidates {
		if !entityMCPSourceAllowed(p, policies, resource, candidate.SourceKey.Kind) {
			return mcp.EntityResolutionResult{}, apierror.Forbidden("entity evidence source is not authorized")
		}
		out.Candidates = append(out.Candidates, mcp.EntityCandidateResult{
			EntityID: candidate.EntityID, EvidenceID: candidate.EvidenceID,
			SupportEvidenceID: candidate.SupportEvidenceID,
			SourceKind:        string(candidate.SourceKey.Kind), SourceRef: candidate.SourceRef,
			AgentID: candidate.SourceKey.AgentID, ObservedAt: candidate.ObservedAt,
		})
	}
	return out, nil
}

func (b mcpEntityBackend) EntityAssign(ctx context.Context, p *auth.Principal, input mcp.EntityAssignInput) (mcp.EntityAssignmentResult, error) {
	ctx, scope, err := entityMCPContext(ctx, p, input.ContextID)
	if err != nil {
		return mcp.EntityAssignmentResult{}, err
	}
	if err := b.requireEntityContext(ctx, p, scope, "agent.write"); err != nil {
		return mcp.EntityAssignmentResult{}, err
	}
	key := entity.SourceKey{AgentID: input.AgentID, Kind: entity.SourceKind(input.SourceKind),
		SourceRef: input.SourceRef}
	if err := tenancy.InTenant(ctx, b.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := store.NewEntityRegistry(b.pool).AssignEntitySource(ctx, sc, key,
			scope.ContextID, input.AnchorEntityID); err != nil {
			return err
		}
		_, err := audit.TenantAppend(ctx, sc, p.UserID, "entity.source.assigned", input.AgentID,
			map[string]any{"source_kind": input.SourceKind, "source_ref": input.SourceRef,
				"context_id": scope.ContextID, "anchor_entity_id": input.AnchorEntityID})
		return err
	}); err != nil {
		return mcp.EntityAssignmentResult{}, entityAdminError(err)
	}
	return mcp.EntityAssignmentResult{AgentID: input.AgentID, SourceKind: input.SourceKind,
		SourceRef: input.SourceRef, ContextID: scope.ContextID, AnchorEntityID: input.AnchorEntityID}, nil
}

func (b mcpEntityBackend) EntityPathContextAssign(ctx context.Context, p *auth.Principal, input mcp.EntityPathContextInput) (mcp.EntityPathContextResult, error) {
	if p == nil || p.TenantID == "" {
		return mcp.EntityPathContextResult{}, apierror.Forbidden("tenant identity is required")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(p.TenantID))
	scope, err := (entity.Scope{TenantID: p.TenantID, ContextID: input.ContextID}).Normalize()
	if err != nil {
		return mcp.EntityPathContextResult{}, entityAPIError(err)
	}
	if err := b.requireEntityContext(ctx, p, scope, "agent.write"); err != nil {
		return mcp.EntityPathContextResult{}, err
	}
	if err := tenancy.InTenant(ctx, b.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := store.NewEntityRegistry(b.pool).AssignPathTestContext(ctx, sc,
			input.TestID, input.ContextID); err != nil {
			return err
		}
		_, err := audit.TenantAppend(ctx, sc, p.UserID, "entity.path_context.assigned", input.TestID,
			map[string]any{"context_id": input.ContextID})
		return err
	}); err != nil {
		return mcp.EntityPathContextResult{}, entityAdminError(err)
	}
	return mcp.EntityPathContextResult{TestID: input.TestID, ContextID: input.ContextID}, nil
}

func (b mcpEntityBackend) EntityPathResolve(ctx context.Context, p *auth.Principal, input mcp.EntityPathResolveInput) (mcp.EntityPathResult, error) {
	if p == nil || p.TenantID == "" {
		return mcp.EntityPathResult{}, apierror.Forbidden("tenant identity is required")
	}
	if b.pathStore == nil {
		return mcp.EntityPathResult{}, apierror.Unavailable("path store is not configured")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(p.TenantID))
	policies, err := b.entitySourcePolicies(ctx, p)
	if err != nil {
		return mcp.EntityPathResult{}, err
	}
	if !mcp.ResourceAllowed(p, permTestRead, policies,
		map[string]string{auth.ResourceTenantKey: p.TenantID}) {
		return mcp.EntityPathResult{}, apierror.Forbidden("test read is required for path identity")
	}
	if err := tenancy.InTenant(ctx, b.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.Tests{}).Get(ctx, sc, input.TestID)
		return err
	}); err != nil {
		return mcp.EntityPathResult{}, entityAPIError(err)
	}
	registry := store.NewEntityRegistry(b.pool)
	binding, err := registry.PathTestBinding(ctx, p.TenantID, input.TestID)
	out := mcp.EntityPathResult{TestID: input.TestID, Status: "unbound", Items: []mcp.EntityPathHopResult{}}
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return mcp.EntityPathResult{}, entityAPIError(err)
	}
	scope := binding.Scope
	resource, err := b.entityResource(ctx, scope)
	if err != nil {
		return mcp.EntityPathResult{}, err
	}
	if !mcp.ResourceAllowed(p, "entities.read", policies, resource) ||
		!mcp.ResourceAllowed(p, permTestRead, policies, resource) {
		return mcp.EntityPathResult{}, apierror.Forbidden("path identity routing context is not authorized")
	}
	// The existence read above can race with a retarget. Resolve history from
	// the target and context captured by the same operator binding read.
	pth, found, err := latestPathAfterBinding(ctx, b.pathStore, p.TenantID, binding)
	if err != nil {
		return mcp.EntityPathResult{}, apierror.Internal("path lookup failed").Wrap(err)
	}
	if !found {
		out.ContextID, out.Status = scope.ContextID, "awaiting_trace"
		return out, nil
	}
	out.ContextID, out.Status = scope.ContextID, "current"
	const maxAddresses = 640
	addresses := make([]string, 0)
	seen := make(map[string]bool)
	canonical := make(map[string]string)
	for _, hop := range pth.Hops {
		for _, node := range hop.Nodes {
			if node.IP == "" {
				continue
			}
			if len(out.Items) >= maxAddresses {
				out.Truncated = true
				continue
			}
			if alias, aliasErr := (entity.AliasKey{Kind: entity.AddressAlias, Value: node.IP}).Normalize(); aliasErr == nil {
				canonical[node.IP] = alias.Value
				if !seen[alias.Value] {
					seen[alias.Value] = true
					addresses = append(addresses, alias.Value)
				}
			}
			out.Items = append(out.Items, mcp.EntityPathHopResult{TTL: hop.TTL,
				IP: node.IP})
		}
	}
	resolved, err := registry.ResolveAddresses(ctx, scope, addresses)
	if err != nil {
		return mcp.EntityPathResult{}, entityAPIError(err)
	}
	projected := make(map[string]mcp.EntityResolutionResult, len(resolved))
	for address, value := range resolved {
		if !entityMCPResolutionAllowed(p, policies, value, resource) {
			return mcp.EntityPathResult{}, apierror.Forbidden("path identity source is not authorized")
		}
		resolution := mcp.EntityResolutionResult{ContextID: scope.ContextID,
			Status: string(value.Status), EntityID: value.EntityID,
			MoreCandidates: value.MoreCandidates,
			Candidates:     make([]mcp.EntityCandidateResult, 0, len(value.Candidates))}
		for _, candidate := range value.Candidates {
			if !entityMCPSourceAllowed(p, policies, resource, candidate.SourceKey.Kind) {
				return mcp.EntityPathResult{}, apierror.Forbidden("path identity source is not authorized")
			}
			resolution.Candidates = append(resolution.Candidates, mcp.EntityCandidateResult{
				EntityID: candidate.EntityID, EvidenceID: candidate.EvidenceID,
				SupportEvidenceID: candidate.SupportEvidenceID,
				SourceKind:        string(candidate.SourceKey.Kind), SourceRef: candidate.SourceRef,
				AgentID: candidate.SourceKey.AgentID, ObservedAt: candidate.ObservedAt})
		}
		projected[address] = resolution
	}
	for i := range out.Items {
		out.Items[i].Resolution = mcp.EntityResolutionResult{
			ContextID: scope.ContextID, Status: "unresolved"}
		if key, ok := canonical[out.Items[i].IP]; ok {
			out.Items[i].Resolution = projected[key]
		}
	}
	return out, nil
}
