// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type flowKubernetesSnapshot struct {
	data        *flowstore.KubernetesQueryData
	reads       []flowstore.RoutingCaptureRead
	owners      []store.CapturedFlowOwner
	inventories []store.KubernetesInventoryAuthorityProof
}

type kubernetesFlowContext struct {
	scope       entity.Scope
	from, until time.Time
	indices     []int
}

func (s *Server) loadFlowKubernetesSnapshot(ctx context.Context, actor *auth.Principal, plan flow.QueryPlan,
	budget flowstore.ExplorerBudget) (flowKubernetesSnapshot, error) {
	if err := s.admitKubernetesFlowReader(ctx, actor, budget); err != nil {
		return flowKubernetesSnapshot{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	var snapshot flowKubernetesSnapshot
	var err error
	if batch, present := ctx.Value(reportFlowBatchKey{}).(*flowstore.PlanBatch); present {
		if batch == nil {
			return snapshot, flowExplorerStoreError(flowstore.ErrExplorerBudget)
		}
		snapshot.reads, err = batch.TimedFlowCaptureReferences(plan.From, plan.To, plan.DataSeries)
	} else {
		snapshot.reads, err = flowstore.ReadTimedFlowCaptureReferences(ctx, s.flowStore, actor.TenantID, plan.From, plan.To, plan.DataSeries)
	}
	if err != nil {
		return flowKubernetesSnapshot{}, flowExplorerStoreError(err)
	}
	var rows []flowstore.KubernetesFlowProjection
	err = s.inFlowKubernetesScope(ctx, actor, func(ctx context.Context, sc tenancy.Scope, current *auth.Principal) error {
		snapshot.owners, err = s.kubernetesCapturedFlowOwners(ctx, sc, current, snapshot.reads, budget)
		if err != nil {
			return err
		}
		rows, snapshot.inventories, err = s.kubernetesFlowAddressProjections(ctx, sc, current, snapshot, budget.MemoryBytes/4)
		return err
	})
	if err != nil {
		return flowKubernetesSnapshot{}, err
	}
	snapshot.data, err = flowstore.NewKubernetesQueryData(ctx, actor.TenantID, rows, budget.MemoryBytes/4)
	if err != nil {
		return flowKubernetesSnapshot{}, flowExplorerStoreError(err)
	}
	return snapshot, nil
}

func (s *Server) admitKubernetesFlowReader(ctx context.Context, actor *auth.Principal, budget flowstore.ExplorerBudget) error {
	bound, present := tenancy.FromContext(ctx)
	if actor == nil || actor.UserID == "" || !present || bound.String() != actor.TenantID {
		return apierror.Forbidden("current tenant user is required for Kubernetes attribution")
	}
	if original := auth.PrincipalFrom(ctx); original != nil && (original.TenantID != actor.TenantID || original.UserID != actor.UserID) {
		return apierror.Forbidden("Kubernetes flow scope does not match the credential")
	}
	if budget.Validate() != nil || s.pool == nil {
		return apierror.Unavailable("Kubernetes flow admission is unavailable")
	}
	return ctx.Err()
}

func (s *Server) inFlowKubernetesScope(ctx context.Context, actor *auth.Principal,
	read func(context.Context, tenancy.Scope, *auth.Principal) error) error {
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return err
	}
	if status != "active" {
		return apierror.Forbidden("current Kubernetes flow tenant is inactive")
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		ctx, current, err := s.currentRoutingAuthority(ctx, sc, actor, ai.PermEntitiesRead)
		if err != nil {
			return err
		}
		if err := s.authorizeNativeFlow(ctx, current); err != nil {
			return err
		}
		return read(ctx, sc, current)
	})
}

func (s *Server) kubernetesCapturedFlowOwners(ctx context.Context, sc tenancy.Scope, current *auth.Principal,
	reads []flowstore.RoutingCaptureRead, budget flowstore.ExplorerBudget) ([]store.CapturedFlowOwner, error) {
	if len(reads) == 0 {
		return nil, ctx.Err()
	}
	profile := store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / 4, WorkUnits: budget.MemoryBytes / 2, StateBytes: budget.MemoryBytes / 4}
	return (store.CapturedFlowOwners{}).ReadInScope(ctx, sc, reads, profile,
		func(ctx context.Context, record entity.ContextRecord, binding store.InterfaceRoleFlowBinding) error {
			resource := entityContextResource(record)
			resource["agent_id"], resource["entity_id"] = binding.AgentID, binding.RouterID
			resource["source_kind"], resource["source_ref"] = string(entity.FlowExporter), binding.Exporter.String()
			return s.authorizeKubernetesFlowResource(ctx, current, resource)
		})
}

func (s *Server) authorizeKubernetesFlowResource(ctx context.Context, current *auth.Principal, resource map[string]string) error {
	for _, permission := range []string{permFlowRead, ai.PermEntitiesRead} {
		if err := s.authorize(ctx, current, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) kubernetesFlowSources(ctx context.Context, sc tenancy.Scope, current *auth.Principal, contextID string) (func(store.KubernetesInventorySource) error, error) {
	record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, contextID)
	if err != nil {
		return nil, entityAPIError(err)
	}
	resource := entityContextResource(record)
	if err := s.authorizeKubernetesFlowResource(ctx, current, resource); err != nil {
		return nil, err
	}
	return func(source store.KubernetesInventorySource) error {
		values := maps.Clone(resource)
		values["agent_id"], values["cluster_id"], values["namespace"] = source.AgentID, source.ClusterID, source.Namespace
		return s.authorizeKubernetesFlowResource(ctx, current, values)
	}, nil
}

func (s *Server) kubernetesFlowAddressProjections(ctx context.Context, sc tenancy.Scope, current *auth.Principal,
	original flowKubernetesSnapshot, memoryBytes int64) ([]flowstore.KubernetesFlowProjection, []store.KubernetesInventoryAuthorityProof, error) {
	if len(original.reads) != len(original.owners) || int64(len(original.reads)) > memoryBytes/2048 {
		return nil, nil, flowExplorerStoreError(flowstore.ErrExplorerBudget)
	}
	groups := make(map[string]*kubernetesFlowContext)
	for i, read := range original.reads {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		owner := original.owners[i]
		from, until, usable := read.Timing.ObservationRange(read.Witness.Input.Protocol, 0)
		if !owner.Available || !usable || from.Before(owner.CurrentOwnerSince) {
			continue
		}
		key := owner.Owner.ContextID
		group := groups[key]
		if group == nil {
			group = &kubernetesFlowContext{scope: owner.Owner.Scope, from: from, until: until}
			groups[key] = group
		}
		if from.Before(group.from) {
			group.from = from
		}
		if until.After(group.until) {
			group.until = until
		}
		group.indices = append(group.indices, i)
	}
	var rows []flowstore.KubernetesFlowProjection
	var inventories []store.KubernetesInventoryAuthorityProof
	perContext := memoryBytes / int64(max(1, len(groups)))
	for _, key := range slices.Sorted(maps.Keys(groups)) {
		group := groups[key]
		authorize, err := s.kubernetesFlowSources(ctx, sc, current, key)
		if err != nil {
			return nil, nil, err
		}
		snapshot, err := store.ReadKubernetesFlowInventoryInScope(ctx, sc, group.scope, group.from, group.until, perContext/2, authorize)
		if err != nil {
			return nil, nil, kubernetesInventoryReadAPIError(err)
		}
		proof, err := snapshot.AuthorityProof(ctx, perContext/2)
		if err != nil {
			return nil, nil, kubernetesInventoryReadAPIError(err)
		}
		inventories = append(inventories, proof)
		bound, known := snapshot.FlowClockError()
		if !known {
			continue
		}
		projection, err := snapshot.AddressProjection(ctx, perContext/2)
		if err != nil {
			return nil, nil, kubernetesInventoryReadAPIError(err)
		}
		rows = appendKubernetesFlowResults(rows, original, group, projection, bound)
	}
	return rows, inventories, ctx.Err()
}

func appendKubernetesFlowResults(rows []flowstore.KubernetesFlowProjection, original flowKubernetesSnapshot,
	group *kubernetesFlowContext, projection store.KubernetesAddressProjection, bound time.Duration) []flowstore.KubernetesFlowProjection {
	for _, i := range group.indices {
		read, owner := original.reads[i], original.owners[i]
		input := read.Witness.Input
		from, until, usable := read.Timing.ObservationRange(input.Protocol, bound)
		if !usable || from.Before(owner.CurrentOwnerSince) {
			continue
		}
		src, _ := projection.Resolve(input.Source, from, until)
		dst, _ := projection.Resolve(input.Destination, from, until)
		if src.UID != "" || dst.UID != "" {
			srcOwner, _ := projection.ResolveWorkload(input.Source, from, until)
			dstOwner, _ := projection.ResolveWorkload(input.Destination, from, until)
			rows = append(rows, flowstore.KubernetesFlowProjection{Scope: group.scope, Capture: read,
				Source: kubernetesFlowEndpoint(src, srcOwner), Destination: kubernetesFlowEndpoint(dst, dstOwner)})
		}
	}
	return rows
}

func kubernetesFlowEndpoint(object, workload store.KubernetesObjectIdentity) flowstore.KubernetesFlowEndpoint {
	switch object.Kind {
	case agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_POD:
		return flowstore.KubernetesFlowEndpoint{Cluster: object.ClusterID, Namespace: object.Namespace, Pod: object.Name,
			PodUID: object.UID, Workload: workload.Name, WorkloadUID: workload.UID}
	case agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_SERVICE:
		return flowstore.KubernetesFlowEndpoint{Cluster: object.ClusterID, Namespace: object.Namespace, Service: object.Name, ServiceUID: object.UID}
	default:
		return flowstore.KubernetesFlowEndpoint{}
	}
}

func (s *Server) recheckFlowKubernetesSnapshot(ctx context.Context, actor *auth.Principal, snapshot flowKubernetesSnapshot,
	budget flowstore.ExplorerBudget) error {
	if err := s.admitKubernetesFlowReader(ctx, actor, budget); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	return s.inFlowKubernetesScope(ctx, actor, func(ctx context.Context, sc tenancy.Scope, current *auth.Principal) error {
		owners, err := s.kubernetesCapturedFlowOwners(ctx, sc, current, snapshot.reads, budget)
		if err != nil {
			return err
		}
		if !slices.EqualFunc(snapshot.owners, owners, func(a, b store.CapturedFlowOwner) bool {
			return a.Reference == b.Reference && a.Available == b.Available && a.Owner == b.Owner &&
				a.CurrentOwnerSince.Equal(b.CurrentOwnerSince)
		}) {
			return apierror.Unavailable("Kubernetes flow source authority changed; run a fresh query")
		}
		return s.recheckFlowKubernetesInventory(ctx, sc, current, snapshot.inventories, budget.MemoryBytes/4)
	})
}

func (s *Server) recheckFlowKubernetesInventory(ctx context.Context, sc tenancy.Scope, current *auth.Principal,
	inventories []store.KubernetesInventoryAuthorityProof, memoryBytes int64) error {
	perContext := memoryBytes / int64(max(1, len(inventories)))
	for _, inventory := range inventories {
		authorize, err := s.kubernetesFlowSources(ctx, sc, current, inventory.Scope.ContextID)
		if err != nil {
			return err
		}
		if err := store.RecheckKubernetesInventoryProofInScope(ctx, sc, inventory, perContext, authorize); err != nil {
			return kubernetesInventoryReadAPIError(err)
		}
	}
	return ctx.Err()
}
