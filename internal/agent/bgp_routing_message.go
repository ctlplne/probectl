// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// SubmitRoutingMessage preserves complete bytes, generation, sequence and clock
// on the existing restricted mTLS connection. A committed refusal is an error,
// even when the service successfully invalidated this exact generation.
func (c *EvidenceClient) SubmitRoutingMessage(ctx context.Context, raw *agentv1.BmpRoutingMessage) (*agentv1.BmpRoutingMessageReceipt, error) {
	if c == nil || raw == nil || raw.Sequence <= 0 || raw.Sequence == math.MaxInt64 {
		return nil, ErrEvidenceBatchInvalid
	}
	id, err := uuid.Parse(raw.Generation)
	if err != nil || id == uuid.Nil || id.String() != raw.Generation {
		return nil, ErrEvidenceBatchInvalid
	}
	c.mu.RLock()
	reconnect := c.needsReconnect
	c.mu.RUnlock()
	if reconnect {
		if err := c.ReconnectAfterRotation(); err != nil {
			return nil, err
		}
	}
	request := &agentv1.SubmitEntityEvidenceRequest{RoutingMessage: raw}
	size := proto.Size(request)
	if size <= 0 || size > math.MaxInt32-4096 {
		return nil, ErrEvidenceBatchInvalid
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c.mu.RLock()
	svc := c.svc
	c.mu.RUnlock()
	if svc == nil {
		return nil, ErrEvidenceBatchInvalid
	}
	response, err := svc.SubmitEntityEvidence(callCtx, request, grpc.MaxCallSendMsgSize(size+4096), grpc.MaxCallRecvMsgSize(1<<20))
	if err != nil {
		return nil, err
	}
	receipt := response.GetRoutingMessage()
	if receipt == nil || response.GetAccepted() != 0 || response.GetUnresolved() != 0 || response.GetFaultsPersisted() != 0 || response.GetRouting() != nil ||
		receipt.Generation != raw.Generation || receipt.Sequence != raw.Sequence {
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
