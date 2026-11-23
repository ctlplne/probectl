// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

func (s *Server) nativeKubernetesTopology(ctx context.Context, actor *auth.Principal, contextID string, at time.Time) (topology.Viz, error) {
	if actor == nil || actor.UserID == "" || actor.TenantID == "" {
		return topology.Viz{}, apierror.Unauthorized("current tenant user is required")
	}
	if bound, present := tenancy.FromContext(ctx); present && bound.String() != actor.TenantID {
		return topology.Viz{}, apierror.Forbidden("Kubernetes topology tenant scope does not match the credential")
	}
	if bound := auth.PrincipalFrom(ctx); bound != nil && (bound.TenantID != actor.TenantID || bound.UserID != actor.UserID) {
		return topology.Viz{}, apierror.Forbidden("Kubernetes topology user scope does not match the credential")
	}
	viewAt := at
	if viewAt.IsZero() {
		viewAt = time.Now().UTC()
	}
	viz := topology.Viz{Tenant: actor.TenantID, At: viewAt, Nodes: []topology.VizNode{}, Edges: []topology.VizEdge{}}
	scope := entity.Scope{TenantID: actor.TenantID, ContextID: contextID}
	if err := s.projectKubernetesTopology(auth.WithPrincipal(ctx, actor), scope, at, &viz, true); err != nil {
		return topology.Viz{}, err
	}
	return viz, nil
}

func (s *Server) projectKubernetesTopology(ctx context.Context, scope entity.Scope, at time.Time, viz *topology.Viz, native bool) error {
	if s.pool == nil {
		return apierror.Unavailable("Kubernetes inventory is unavailable")
	}
	actor := auth.PrincipalFrom(ctx)
	if actor == nil || actor.TenantID != scope.TenantID {
		return apierror.Forbidden("Kubernetes inventory requires a current tenant user")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if budget.Validate() != nil {
		return apierror.Unavailable("Kubernetes inventory query admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(ctx, tenancy.ID(scope.TenantID)), budget.ExecutionLimit)
	ctx, flushDenial := scopedABACDenial(ctx)
	releaseQuery := func() {}
	release := func() {
		releaseQuery()
		flushDenial(s)
		cancel()
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	if s.fairnessGate != nil {
		done, err := s.fairnessGate.BeginQuery(ctx, scope.TenantID)
		if err != nil {
			return tagQueryAdmissionError(err)
		}
		releaseQuery = done
	}
	memory := min(budget.MemoryBytes/4, budget.ResponseBytes)
	var snapshot store.KubernetesInventorySnapshot
	var projection store.KubernetesTopologyProjection
	if err := s.inKubernetesTopologyScope(ctx, actor, scope.ContextID,
		func(ctx context.Context, sc tenancy.Scope, authorize func(store.KubernetesInventorySource) error) error {
			var err error
			snapshot, err = store.ReadKubernetesTopologyInScope(ctx, sc, scope, at, memory, authorize)
			if err != nil {
				return err
			}
			projection, err = snapshot.TopologyProjection(ctx, memory)
			return err
		}); err != nil {
		return kubernetesInventoryReadAPIError(err)
	}
	check := func(active context.Context) error {
		if err := active.Err(); err != nil {
			return err
		}
		return s.inKubernetesTopologyScope(ctx, actor, scope.ContextID,
			func(ctx context.Context, sc tenancy.Scope, authorize func(store.KubernetesInventorySource) error) error {
				return store.RecheckKubernetesInventoryInScope(ctx, sc, snapshot, memory, authorize)
			})
	}
	if native {
		if err := mcp.RetainNativePublication(ctx, check, release); err != nil {
			return err
		}
		retained = true
	} else if err := check(ctx); err != nil {
		return kubernetesInventoryReadAPIError(err)
	}
	appendKubernetesTopology(viz, projection)
	return nil
}

func (s *Server) inKubernetesTopologyScope(ctx context.Context, actor *auth.Principal, contextID string,
	read func(context.Context, tenancy.Scope, func(store.KubernetesInventorySource) error) error) error {
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		ctx, principal, err := s.currentRoutingAuthority(ctx, sc, actor, ai.PermEntitiesRead)
		if err != nil {
			return err
		}
		record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, contextID)
		if err != nil {
			return entityAPIError(err)
		}
		resource := entityContextResource(record)
		authorize := func(attributes map[string]string) error {
			for _, perm := range []string{ai.PermEntitiesRead, ai.PermTopologyRead} {
				if err := s.authorize(ctx, principal, perm, auth.RBACGlobal, attributes); err != nil {
					return err
				}
			}
			return nil
		}
		if err := authorize(resource); err != nil {
			return err
		}
		return read(ctx, sc, func(source store.KubernetesInventorySource) error {
			attributes := maps.Clone(resource)
			attributes["agent_id"], attributes["cluster_id"], attributes["namespace"] = source.AgentID, source.ClusterID, source.Namespace
			return authorize(attributes)
		})
	})
}

func appendKubernetesTopology(viz *topology.Viz, projection store.KubernetesTopologyProjection) {
	for _, object := range projection.Objects {
		kind := strings.ToLower(strings.TrimPrefix(object.Kind.String(), "KUBERNETES_INVENTORY_KIND_"))
		viz.Nodes = append(viz.Nodes, topology.VizNode{
			ID: object.ID, Kind: "kubernetes_" + kind, Label: object.Name,
			Kubernetes: &topology.VizKubernetesObject{ClusterID: object.ClusterID, Namespace: object.Namespace,
				UID: object.UID, ObservedAt: object.ObservedAt},
		})
	}
	for _, link := range projection.Links {
		kind := "kubernetes_owner"
		if link.Kind == agentv1.KubernetesInventoryRelationshipKind_KUBERNETES_INVENTORY_RELATIONSHIP_KIND_SERVICE_BACKEND {
			kind = "kubernetes_backend"
		}
		viz.Edges = append(viz.Edges, topology.VizEdge{From: link.From, To: link.To, Kind: kind, ObservedAt: link.ObservedAt})
	}
}

func kubernetesInventoryReadAPIError(err error) error {
	switch {
	case errors.Is(err, store.ErrKubernetesInventoryBudget):
		return apierror.RateLimited("Kubernetes inventory exceeds the query budget")
	case errors.Is(err, store.ErrKubernetesInventoryAuthority):
		return apierror.Unavailable("Kubernetes inventory authority changed; retry the query")
	default:
		return err
	}
}
