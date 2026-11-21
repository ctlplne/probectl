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

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/threat/dnstap"
)

// SubmitResolverDNS sends only reduced, fixed-clock counters through the
// existing evidence-only mTLS connection. Raw capture files stay local.
func (c *EvidenceClient) SubmitResolverDNS(ctx context.Context, source string, capture dnstap.ClosedCapture) (*agentv1.ResolverDNSCaptureReceipt, error) {
	if c == nil || !dnstap.ValidSourceRef(source) || capture.Validate(time.Now()) != nil {
		return nil, ErrEvidenceBatchInvalid
	}
	data := &agentv1.ResolverDNSCapture{ConfiguredRef: source, ParsedFrames: capture.Frames, SelectedFrames: capture.Selected}
	for _, interval := range capture.Intervals {
		data.Intervals = append(data.Intervals, &agentv1.ResolverDNSInterval{
			FromUnixNanos: interval.From.UnixNano(), ClientResponses: interval.Responses, NameErrors: interval.NameErrors,
			ServerFailures: interval.ServerFailure, Truncated: interval.Truncated,
		})
	}
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(data)
	if err != nil {
		return nil, ErrEvidenceBatchInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, evidenceDeliveryTimeout)
	defer cancel()
	response, err := c.submitExclusiveEvidence(ctx, &agentv1.SubmitEntityEvidenceRequest{ResolverDns: data})
	if err != nil {
		return nil, err
	}
	receipt := response.GetResolverDns()
	if !exclusiveEvidenceReceipt(response, "resolver_dns") || receipt == nil || receipt.GetIntervals() != uint32(len(capture.Intervals)) ||
		receipt.GetPressureSignals() > 2*receipt.GetIntervals() || !bytes.Equal(receipt.GetEvidenceDigest(), crypto.Hash(wire)) ||
		len(receipt.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrEvidenceBatchInvalid
	}
	return receipt, nil
}

func exclusiveEvidenceReceipt(response *agentv1.SubmitEntityEvidenceResponse, allowed protoreflect.Name) bool {
	if response == nil || len(response.ProtoReflect().GetUnknown()) != 0 {
		return false
	}
	exclusive := true
	response.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		exclusive = field.Name() == allowed
		return exclusive
	})
	return exclusive
}
