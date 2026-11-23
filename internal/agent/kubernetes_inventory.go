// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"context"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// SubmitKubernetesInventory sends one operation on the existing evidence
// channel. The collector retains its generation ID, manifest and ordered
// parts across a retry. A legacy generic acknowledgement cannot finish it.
func (c *EvidenceClient) SubmitKubernetesInventory(ctx context.Context, upload *agentv1.KubernetesInventoryUpload) (*agentv1.KubernetesInventoryReceipt, error) {
	if upload == nil || !validEvidenceNonce(upload.BindingId) || !validEvidenceNonce(upload.GenerationId) ||
		len(upload.ProtoReflect().GetUnknown()) != 0 || upload.Operation == nil {
		return nil, ErrEvidenceBatchInvalid
	}
	response, err := c.submitExclusiveEvidence(ctx, &agentv1.SubmitEntityEvidenceRequest{KubernetesInventory: upload})
	if err != nil {
		return nil, err
	}
	receipt := response.GetKubernetesInventory()
	if receipt == nil || receipt.GenerationId != upload.GenerationId || len(receipt.ProtoReflect().GetUnknown()) != 0 ||
		!exclusiveEvidenceReceipt(response, "kubernetes_inventory") {
		return nil, ErrEvidenceBatchInvalid
	}
	switch operation := upload.Operation.(type) {
	case *agentv1.KubernetesInventoryUpload_Begin:
		manifest := operation.Begin.GetManifest()
		if manifest == nil || !bytes.Equal(receipt.PayloadDigest, operation.Begin.PayloadDigest) || receipt.NextPart > manifest.Parts ||
			receipt.RetainedRows > manifest.Rows || (receipt.Published && (receipt.NextPart != manifest.Parts || receipt.RetainedRows != manifest.Rows)) {
			return nil, ErrEvidenceBatchInvalid
		}
	case *agentv1.KubernetesInventoryUpload_Append:
		if operation.Append == nil || receipt.Published || receipt.NextPart <= operation.Append.Index || len(receipt.PayloadDigest) != 0 {
			return nil, ErrEvidenceBatchInvalid
		}
	case *agentv1.KubernetesInventoryUpload_Publish:
		if operation.Publish == nil || !receipt.Published || len(receipt.PayloadDigest) != 32 {
			return nil, ErrEvidenceBatchInvalid
		}
	default:
		return nil, ErrEvidenceBatchInvalid
	}
	return receipt, nil
}
