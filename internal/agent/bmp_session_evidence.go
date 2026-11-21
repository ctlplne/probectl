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
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// SubmitBMPSessionEvidence sends one original router observation over the
// existing restricted mTLS channel and validates the exact durable receipt.
func (c *EvidenceClient) SubmitBMPSessionEvidence(ctx context.Context, raw *agentv1.BmpSessionEvidence) error {
	if raw == nil || !validEvidenceNonce(raw.ConnectionId) || raw.Sequence <= 0 || raw.Sequence == math.MaxInt64 ||
		raw.ConfiguredRef == "" || raw.OriginSerial == "" || raw.ObservedUnixNanos <= 0 || !validBMPSessionPayload(raw) ||
		len(raw.Frame) > 1<<20 || len(raw.ProtoReflect().GetUnknown()) != 0 {
		return ErrEvidenceBatchInvalid
	}
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(raw)
	if err != nil {
		return ErrEvidenceBatchInvalid
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := c.submitExclusiveEvidence(callCtx, &agentv1.SubmitEntityEvidenceRequest{BmpSessionEvidence: raw})
	if err != nil {
		return err
	}
	receipt := response.GetBmpSessionEvidence()
	if receipt == nil || !exclusiveEvidenceReceipt(response, "bmp_session_evidence") || len(receipt.ProtoReflect().GetUnknown()) != 0 ||
		receipt.ConnectionId != raw.ConnectionId || receipt.Sequence != raw.Sequence || !bytes.Equal(receipt.EvidenceDigest, crypto.Hash(wire)) {
		return ErrEvidenceBatchInvalid
	}
	return nil
}

func validBMPSessionPayload(raw *agentv1.BmpSessionEvidence) bool {
	if raw.UpdateWindow != nil {
		return !raw.TransportClosed && len(raw.Frame) == 0 && len(raw.UpdateWindow.PeerHeader) == 42 && len(raw.UpdateWindow.ProtoReflect().GetUnknown()) == 0
	}
	return raw.TransportClosed == (len(raw.Frame) == 0)
}
