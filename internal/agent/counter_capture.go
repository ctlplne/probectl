// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// CaptureCounters attests original bytes through the existing evidence mTLS
// channel. The caller's sender must match this client's certificate identity.
// Its returned receipt is a write acknowledgment, never a reusable read grant.
func (c *EvidenceClient) CaptureCounters(ctx context.Context, sender string, digest [32]byte, input entity.CounterCaptureInput) (entity.CounterCaptureReference, error) {
	none := entity.CounterCaptureReference{}
	if c == nil {
		return none, ErrEvidenceBatchInvalid
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	c.mu.RLock()
	reconnect := c.needsReconnect
	c.mu.RUnlock()
	if reconnect {
		if err := c.ReconnectAfterRotation(); err != nil {
			return none, err
		}
	}
	c.mu.RLock()
	tenant, boundSender, svc := c.tenantID, c.agentID, c.svc
	c.mu.RUnlock()
	if sender != boundSender || svc == nil {
		return none, ErrEvidenceBatchInvalid
	}
	expected, err := entity.CounterCaptureKey(tenant, boundSender, digest, input)
	if err != nil {
		return none, ErrEvidenceBatchInvalid
	}
	request := &agentv1.SubmitEntityEvidenceRequest{DeviceCounter: &agentv1.DeviceCounterWitness{
		ContractVersion: "device_counter_capture_v1", ConfiguredRef: input.ConfiguredTarget, RawDigest: append([]byte(nil), digest[:]...),
		PollStartedUnixNanos: input.PollStartedAt.UnixNano(), PollCompletedUnixNanos: input.PollCompletedAt.UnixNano(), PointCount: input.PointCount,
	}}
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := svc.SubmitEntityEvidence(callCtx, request, grpc.MaxCallSendMsgSize(proto.Size(request)+4096), grpc.MaxCallRecvMsgSize(4096))
	if err != nil {
		return none, err
	}
	receipt := response.GetDeviceCounter()
	if receipt == nil || !bytes.Equal(receipt.Key, expected[:]) || receipt.CapturedUnixNanos <= 0 ||
		response.GetAccepted() != 0 || response.GetUnresolved() != 0 || response.GetFaultsPersisted() != 0 || (response.GetIcmpMeasurementsPersisted() != 0 || response.GetProbeOutcomesPersisted() != 0) || response.GetRouting() != nil ||
		response.GetRoutingMessage() != nil || response.GetFlowRouting() != nil || hasPublicRoutingReceipt(response) ||
		len(response.ProtoReflect().GetUnknown()) != 0 || len(receipt.ProtoReflect().GetUnknown()) != 0 {
		return none, ErrEvidenceBatchInvalid
	}
	return entity.CounterCaptureReference{Key: expected, CapturedAt: time.Unix(0, receipt.CapturedUnixNanos)}, nil
}
