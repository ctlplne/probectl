// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type flowKubernetesOwnerValidity struct {
	Capture  flowRoutingCaptureSelector `json:"capture"`
	Context  string                     `json:"context_id"`
	Source   string                     `json:"source_id"`
	Assigned time.Time                  `json:"assigned_at"`
}

type flowKubernetesValidity struct {
	Digest    string                                    `json:"digest"`
	Owners    []flowKubernetesOwnerValidity             `json:"owners"`
	Inventory []store.KubernetesInventoryAuthorityProof `json:"inventory"`
}

func encodeFlowKubernetesValidity(ctx context.Context, snapshot flowKubernetesSnapshot, digest string, memoryBytes int64) (json.RawMessage, error) {
	if !canonicalFlowRoutingDigest(digest) || len(snapshot.reads) != len(snapshot.owners) || int64(len(snapshot.reads)) > memoryBytes/4096 {
		return nil, flowstore.ErrSnapshotInputs
	}
	proof := flowKubernetesValidity{Digest: digest, Inventory: snapshot.inventories}
	for i, owner := range snapshot.owners {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if owner.Available {
			proof.Owners = append(proof.Owners, flowKubernetesOwnerValidity{
				Capture: encodeFlowCaptureSelector(snapshot.reads[i]), Context: owner.Owner.ContextID,
				Source: owner.Owner.SourceID, Assigned: owner.CurrentOwnerSince.UTC(),
			})
		}
	}
	encoded, err := json.Marshal(proof)
	if int64(len(encoded)) > memoryBytes {
		return nil, flowstore.ErrExplorerBudget
	}
	return encoded, err
}

func (source *flowSnapshotSource) validateKubernetesAuthorization(ctx context.Context, scope flowsnapshot.Scope, receipt flowSnapshotValidity) error {
	usesKubernetes := false
	for _, input := range receipt.Inputs {
		usesKubernetes = usesKubernetes || flowSnapshotInputUsesKubernetes(input)
	}
	if !usesKubernetes && len(receipt.Kubernetes) == 0 {
		return nil
	}
	actor := auth.PrincipalFrom(ctx)
	if !usesKubernetes || len(receipt.Kubernetes) != len(receipt.Inputs) || actor == nil || actor.TenantID != scope.TenantID || actor.UserID != scope.Owner {
		return apierror.Forbidden("current Kubernetes source authority is required; run a fresh query")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, source.server.flowStore)
	for i, input := range receipt.Inputs {
		raw := receipt.Kubernetes[i]
		if !flowSnapshotInputUsesKubernetes(input) {
			if !bytes.Equal(raw, []byte("null")) {
				return flowExplorerStoreError(flowstore.ErrSnapshotInputs)
			}
			continue
		}
		var proof *flowKubernetesValidity
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&proof); err != nil {
			return flowExplorerStoreError(flowstore.ErrSnapshotInputs)
		}
		if err := source.server.recheckFlowKubernetesValidity(ctx, actor, proof, budget); err != nil {
			return err
		}
	}
	return nil
}

func flowSnapshotInputUsesKubernetes(input flowstore.SnapshotInputs) bool {
	for _, name := range input.Fields {
		if _, _, ok := flow.KubernetesQueryField(name); ok {
			return true
		}
	}
	return false
}

func (s *Server) recheckFlowKubernetesValidity(ctx context.Context, actor *auth.Principal, proof *flowKubernetesValidity,
	budget flowstore.ExplorerBudget) error {
	if err := s.admitKubernetesFlowReader(ctx, actor, budget); err != nil {
		return err
	}
	if proof == nil || !canonicalFlowRoutingDigest(proof.Digest) || int64(len(proof.Owners)) > budget.MemoryBytes/4/4096 {
		return flowExplorerStoreError(flowstore.ErrSnapshotInputs)
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	reads := make([]flowstore.RoutingCaptureRead, len(proof.Owners))
	for i, owner := range proof.Owners {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, err := decodeFlowCaptureSelector(actor.TenantID, owner.Capture)
		if err != nil {
			return flowExplorerStoreError(err)
		}
		reads[i] = read
	}
	return s.inFlowKubernetesScope(ctx, actor, func(ctx context.Context, sc tenancy.Scope, current *auth.Principal) error {
		owners, err := s.kubernetesCapturedFlowOwners(ctx, sc, current, reads, budget)
		if err != nil {
			return err
		}
		if len(owners) != len(proof.Owners) {
			return flowExplorerStoreError(flowstore.ErrSnapshotInputs)
		}
		for i, owner := range owners {
			original := proof.Owners[i]
			if !owner.Available || owner.Reference != reads[i].Ref || owner.Owner.ContextID != original.Context ||
				owner.Owner.SourceID != original.Source || !owner.CurrentOwnerSince.Equal(original.Assigned) {
				return apierror.Forbidden("Kubernetes flow source authority changed; run a fresh query")
			}
		}
		return s.recheckFlowKubernetesInventory(ctx, sc, current, proof.Inventory, budget.MemoryBytes/4)
	})
}
