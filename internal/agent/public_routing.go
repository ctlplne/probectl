// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"math"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func hasPublicRoutingReceipt(response *agentv1.SubmitEntityEvidenceResponse) bool {
	return response.GetPublicRouting() != nil || response.GetPublicRoutingMessage() != nil
}

// StagePublicRoutingSource submits an original whole peer table over the
// restricted evidence mTLS channel. The caller owns its deadline and retains
// the same observation UUID, capture time and bytes across a retry.
func (c *EvidenceClient) StagePublicRoutingSource(ctx context.Context, raw *agentv1.PublicRoutingPeerTable) (*agentv1.PublicRoutingStagingReceipt, error) {
	if raw == nil || !validPublicRoutingNonce(raw.GetObservationId()) || raw.GetConfiguredRef() == "" || raw.GetObservedUnixNanos() <= 0 || len(raw.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrEvidenceBatchInvalid
	}
	response, err := c.submitPublicRouting(ctx, &agentv1.SubmitEntityEvidenceRequest{PublicRoutingPeerTable: raw})
	if err != nil {
		return nil, err
	}
	receipt := response.GetPublicRouting()
	if receipt == nil || receipt.SnapshotId != raw.ObservationId || len(receipt.ProtoReflect().GetUnknown()) != 0 || response.GetPublicRoutingMessage() != nil || !publicRoutingOnlyResponse(response) {
		return nil, ErrEvidenceBatchInvalid
	}
	switch receipt.Status {
	case "staged", "replayed":
		return receipt, nil
	case "invalidated":
		return receipt, ErrEvidenceBatchInvalid
	default:
		return nil, ErrEvidenceBatchInvalid
	}
}

// SubmitPublicRoutingMessage preserves original source bytes and ordered EOF
// or reset. No interpreted path, canonical scope or view handle is sent.
func (c *EvidenceClient) SubmitPublicRoutingMessage(ctx context.Context, raw *agentv1.PublicRoutingMessage) (*agentv1.PublicRoutingMessageReceipt, error) {
	if raw == nil || !validPublicRoutingNonce(raw.GetSnapshotId()) || raw.ConfiguredRef == "" || raw.ObservedUnixNanos <= 0 || raw.Sequence <= 0 || raw.Sequence == math.MaxInt64 || raw.Complete && raw.SourceReset || (len(raw.Record) == 0) != (raw.Complete || raw.SourceReset) || len(raw.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrEvidenceBatchInvalid
	}
	response, err := c.submitPublicRouting(ctx, &agentv1.SubmitEntityEvidenceRequest{PublicRoutingMessage: raw})
	if err != nil {
		return nil, err
	}
	receipt := response.GetPublicRoutingMessage()
	if receipt == nil || receipt.SnapshotId != raw.SnapshotId || receipt.Sequence != raw.Sequence || len(receipt.ProtoReflect().GetUnknown()) != 0 || response.GetPublicRouting() != nil || !publicRoutingOnlyResponse(response) {
		return nil, ErrEvidenceBatchInvalid
	}
	switch receipt.Status {
	case "applied", "replayed":
		return receipt, nil
	case "invalidated":
		if raw.SourceReset {
			return receipt, nil
		}
		return receipt, ErrEvidenceBatchInvalid
	default:
		return nil, ErrEvidenceBatchInvalid
	}
}

func validPublicRoutingNonce(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}

func publicRoutingOnlyResponse(response *agentv1.SubmitEntityEvidenceResponse) bool {
	return response != nil && response.GetAccepted() == 0 && response.GetUnresolved() == 0 && response.GetFaultsPersisted() == 0 && response.GetIcmpMeasurementsPersisted() == 0 && response.GetProbeOutcomesPersisted() == 0 && response.GetInterfaceStatesPersisted() == 0 && response.GetRouting() == nil && response.GetRoutingMessage() == nil && response.GetFlowRouting() == nil && response.GetDeviceCounter() == nil && len(response.ProtoReflect().GetUnknown()) == 0
}

func (c *EvidenceClient) submitPublicRouting(ctx context.Context, request *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	if c == nil {
		return nil, ErrEvidenceBatchInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.RLock()
	reconnect := c.needsReconnect
	c.mu.RUnlock()
	if reconnect {
		if err := c.ReconnectAfterRotation(); err != nil {
			return nil, err
		}
	}
	size := proto.Size(request)
	if size <= 0 || size > math.MaxInt32-4096 {
		return nil, ErrEvidenceBatchInvalid
	}
	c.mu.RLock()
	svc := c.svc
	c.mu.RUnlock()
	if svc == nil {
		return nil, ErrEvidenceBatchInvalid
	}
	return svc.SubmitEntityEvidence(ctx, request, grpc.MaxCallSendMsgSize(size+4096), grpc.MaxCallRecvMsgSize(1<<20))
}
