// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"math"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const kubernetesInventoryUploadLease = 5 * time.Minute

// KubernetesInventoryAdmission validates the exclusive envelope and returns
// the actual record charge for the existing tenant evidence meter.
func KubernetesInventoryAdmission(upload *agentv1.KubernetesInventoryUpload) (int, error) {
	if !completeKubernetesMessage(upload) || !canonicalKubernetesUploadID(upload.BindingId) ||
		!canonicalKubernetesUploadID(upload.GenerationId) {
		return 0, ErrKubernetesInventoryInput
	}
	switch input := upload.Operation.(type) {
	case *agentv1.KubernetesInventoryUpload_Begin:
		begin := input.Begin
		if !completeKubernetesMessage(begin) || !completeKubernetesMessage(begin.Manifest) ||
			len(begin.PayloadDigest) != 32 || !validKubernetesInventoryWindows(begin.Manifest.Windows) {
			return 0, ErrKubernetesInventoryInput
		}
		if begin.Manifest.Rows > entity.KubernetesInventoryGenerationRows || begin.Manifest.PayloadBytes > entity.KubernetesInventoryGenerationBytes {
			return 0, ErrKubernetesInventoryBudget
		}
		return len(begin.Manifest.Windows), nil
	case *agentv1.KubernetesInventoryUpload_Append:
		part := input.Append
		if !completeKubernetesMessage(part) || len(part.Rows) == 0 || len(part.Rows) > entity.KubernetesInventoryPartRows {
			return 0, ErrKubernetesInventoryInput
		}
		for _, raw := range part.Rows {
			if !validKubernetesInventoryRow(raw) {
				return 0, ErrKubernetesInventoryInput
			}
		}
		return len(part.Rows), nil
	case *agentv1.KubernetesInventoryUpload_Publish:
		if completeKubernetesMessage(input.Publish) {
			return 1, nil
		}
	}
	return 0, ErrKubernetesInventoryInput
}

// Each generation is one complete list/watch bracket per observed resource.
// Distinct resource windows can overlap in time but cannot provide two
// different originals for the same kind in one generation.
func validKubernetesInventoryWindows(windows []*agentv1.KubernetesInventoryWindow) bool {
	const kinds = agentv1.KubernetesInventoryKind_KUBERNETES_INVENTORY_KIND_REPLICATION_CONTROLLER
	if len(windows) == 0 || len(windows) > int(kinds) {
		return false
	}
	var seen [kinds + 1]bool
	for _, window := range windows {
		if !completeKubernetesMessage(window) || !knownKubernetesInventoryKind(window.Kind) || seen[window.Kind] {
			return false
		}
		seen[window.Kind] = true
	}
	return true
}

// WriteKubernetesInventoryInScope requires an evidence SVID and a tenant
// transaction running inside the deployment writer fence. The current source
// binding determines cluster, namespace and routing scope on every operation.
func WriteKubernetesInventoryInScope(ctx context.Context, sc tenancy.Scope, agent, serial string,
	upload *agentv1.KubernetesInventoryUpload) (*agentv1.KubernetesInventoryReceipt, error) {
	if _, err := KubernetesInventoryAdmission(upload); err != nil {
		return nil, err
	}
	scope, err := lockKubernetesUploadAuthority(ctx, sc, agent, serial, upload.BindingId, upload.GenerationId)
	if err != nil {
		return nil, err
	}
	var position kubernetesUploadPosition
	var digest []byte
	marshal := proto.MarshalOptions{Deterministic: true}
	switch input := upload.Operation.(type) {
	case *agentv1.KubernetesInventoryUpload_Begin:
		begin := input.Begin
		for _, raw := range begin.Manifest.Windows {
			if _, err := inventoryWindow(raw, scope); err != nil {
				return nil, err
			}
		}
		wire, err := marshal.Marshal(begin.Manifest)
		if err != nil {
			return nil, ErrKubernetesInventoryInput
		}
		digest = begin.PayloadDigest
		position, err = openKubernetesInventoryUpload(ctx, sc, scope, kubernetesUploadManifest{Body: wire, Digest: digest,
			Parts: begin.Manifest.Parts, Rows: begin.Manifest.Rows, Bytes: begin.Manifest.PayloadBytes}, scope.CheckedAt.Add(kubernetesInventoryUploadLease))
		if err != nil {
			return nil, err
		}
	case *agentv1.KubernetesInventoryUpload_Append:
		wire, err := marshal.Marshal(input.Append)
		if err != nil {
			return nil, ErrKubernetesInventoryInput
		}
		position, err = appendKubernetesInventoryPart(ctx, sc, scope, input.Append.Index, len(input.Append.Rows), wire)
		if err != nil {
			return nil, err
		}
	case *agentv1.KubernetesInventoryUpload_Publish:
		position, digest, err = publishKubernetesInventory(ctx, sc, scope)
		if err != nil {
			return nil, err
		}
	}
	if position.Next < 0 || position.Next > math.MaxUint32 || position.Rows < 0 {
		return nil, ErrKubernetesInventoryInput
	}
	return &agentv1.KubernetesInventoryReceipt{GenerationId: scope.GenerationID, NextPart: uint32(position.Next),
		RetainedRows: uint64(position.Rows), PayloadDigest: digest, Published: position.Published}, nil
}
