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

// StageRoutingPeer submits complete observed bytes on the existing restricted
// evidence mTLS connection. The nonce/time must survive a retry unchanged.
// Returned handles identify PRIVATE staging only; they are not published routes.
func (c *EvidenceClient) StageRoutingPeer(ctx context.Context, raw *agentv1.BmpRoutingPeerUp) (*agentv1.BmpRoutingStagingReceipt, error) {
	if c == nil || raw == nil {
		return nil, ErrEvidenceBatchInvalid
	}
	nonce, err := uuid.Parse(raw.ObservationId)
	if err != nil || nonce == uuid.Nil || nonce.String() != raw.ObservationId {
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
	request := &agentv1.SubmitEntityEvidenceRequest{RoutingPeerUp: raw}
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
	receipt := response.GetRouting()
	if receipt == nil || hasPublicRoutingReceipt(response) || response.GetDeviceCounter() != nil || response.GetFlowRouting() != nil || response.GetRoutingMessage() != nil || response.GetAccepted() != 0 || response.GetUnresolved() != 0 || response.GetFaultsPersisted() != 0 || (response.GetIcmpMeasurementsPersisted() != 0 || response.GetProbeOutcomesPersisted() != 0) {
		return nil, ErrEvidenceBatchInvalid
	}
	switch receipt.Status {
	case "staged", "replayed":
		var seen [3]bool
		ids := map[string]bool{}
		if len(receipt.Views) == 0 {
			return nil, ErrEvidenceBatchInvalid
		}
		for _, view := range receipt.Views {
			id, err := uuid.Parse(view.GetId())
			afi := view.GetAfi()
			if err != nil || id == uuid.Nil || id.String() != view.GetId() || view.GetGeneration() != raw.ObservationId || afi < 1 || afi > 2 || view.GetSafi() != 1 || seen[afi] || ids[view.GetId()] {
				return nil, ErrEvidenceBatchInvalid
			}
			seen[afi] = true
			ids[view.GetId()] = true
		}
	case "invalidated":
		return receipt, ErrEvidenceBatchInvalid
	default:
		return nil, ErrEvidenceBatchInvalid
	}
	return receipt, nil
}
