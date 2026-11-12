// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"context"
	"math"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func flowWitnessKey(tenant, sender string, raw *agentv1.FlowRoutingWitness) ([32]byte, error) {
	if raw == nil || len(raw.RawDigest) != 32 || len(raw.ProtoReflect().GetUnknown()) != 0 {
		return [32]byte{}, ErrEvidenceBatchInvalid
	}
	exporter, err := netip.ParseAddr(raw.ExporterAddress)
	if err != nil {
		return [32]byte{}, ErrEvidenceBatchInvalid
	}
	source, err := netip.ParseAddr(raw.SourceAddress)
	if err != nil {
		return [32]byte{}, ErrEvidenceBatchInvalid
	}
	destination, err := netip.ParseAddr(raw.DestinationAddress)
	if err != nil {
		return [32]byte{}, ErrEvidenceBatchInvalid
	}
	var digest [32]byte
	copy(digest[:], raw.RawDigest)
	return entity.FlowCaptureKey(tenant, sender, digest, entity.FlowCaptureInput{Exporter: exporter.Unmap(), Source: source.Unmap(), Destination: destination.Unmap(), Protocol: raw.FlowProtocol, Domain: raw.ObservationDomain})
}

// SubmitFlowRouting uses only the existing evidence mTLS channel. The complete
// ordered receipt must match this client's certificate-bound identity and every
// original tuple/digest. Receipts contain no route data or reusable read grant.
func (c *EvidenceClient) SubmitFlowRouting(ctx context.Context, raw []*agentv1.FlowRoutingWitness) ([]*agentv1.FlowRoutingCapture, error) {
	if c == nil || len(raw) == 0 {
		return nil, ErrEvidenceBatchInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.RLock()
	reconnect, tenant, sender := c.needsReconnect, c.tenantID, c.agentID
	c.mu.RUnlock()
	if reconnect {
		if err := c.ReconnectAfterRotation(); err != nil {
			return nil, err
		}
	}
	expected := make([][32]byte, len(raw))
	for i, witness := range raw {
		key, err := flowWitnessKey(tenant, sender, witness)
		if err != nil {
			return nil, ErrEvidenceBatchInvalid
		}
		expected[i] = key
	}
	request := &agentv1.SubmitEntityEvidenceRequest{FlowRouting: &agentv1.FlowRoutingWitnessBatch{ContractVersion: "flow_capture_v1", Observations: raw}}
	size := proto.Size(request)
	if size <= 0 || size > math.MaxInt32-4096 || len(raw) > (math.MaxInt32-4096)/128 {
		return nil, ErrEvidenceBatchInvalid
	}
	// A configured complete raw batch can require more than the generic
	// evidence call's five seconds. Match the receiver's finite operation
	// budget; never trim witnesses to fit a client-only deadline.
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c.mu.RLock()
	svc := c.svc
	c.mu.RUnlock()
	if svc == nil {
		return nil, ErrEvidenceBatchInvalid
	}
	response, err := svc.SubmitEntityEvidence(callCtx, request, grpc.MaxCallSendMsgSize(size+4096), grpc.MaxCallRecvMsgSize(len(raw)*128+4096))
	if err != nil {
		return nil, err
	}
	batch := response.GetFlowRouting()
	if batch == nil || hasPublicRoutingReceipt(response) || response.GetDeviceCounter() != nil || response.GetAccepted() != 0 || response.GetUnresolved() != 0 || response.GetFaultsPersisted() != 0 || response.GetIcmpMeasurementsPersisted() != 0 || response.GetRouting() != nil || response.GetRoutingMessage() != nil || len(response.ProtoReflect().GetUnknown()) != 0 || len(batch.ProtoReflect().GetUnknown()) != 0 || len(batch.Captures) != len(expected) {
		return nil, ErrEvidenceBatchInvalid
	}
	out := make([]*agentv1.FlowRoutingCapture, len(expected))
	for i, capture := range batch.Captures {
		if capture == nil || !bytes.Equal(capture.Key, expected[i][:]) || capture.CapturedUnixNanos <= 0 || len(capture.ProtoReflect().GetUnknown()) != 0 {
			return nil, ErrEvidenceBatchInvalid
		}
		out[i] = proto.Clone(capture).(*agentv1.FlowRoutingCapture)
	}
	return out, nil
}
