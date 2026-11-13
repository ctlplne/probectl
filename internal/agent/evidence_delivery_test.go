// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type delayedEvidenceReceipt struct {
	agentv1.AgentServiceClient
	wait time.Duration
}

func (s delayedEvidenceReceipt) SubmitEntityEvidence(ctx context.Context, request *agentv1.SubmitEntityEvidenceRequest, _ ...grpc.CallOption) (*agentv1.SubmitEntityEvidenceResponse, error) {
	timer := time.NewTimer(s.wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return &agentv1.SubmitEntityEvidenceResponse{Accepted: uint32(len(request.GetObservations()))}, nil
	}
}

func TestEvidenceDeliveryWaitsForCompleteReceiptAndHonorsEarlierCancellation(t *testing.T) {
	const agentID = "22222222-2222-4222-8222-222222222222"
	client := &EvidenceClient{tenantID: "11111111-1111-4111-8111-111111111111", agentID: agentID, svc: delayedEvidenceReceipt{wait: 5250 * time.Millisecond}}
	claim := entity.Observation{ID: "33333333-3333-4333-8333-333333333333", Source: entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"},
		Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.1"}, SourceRef: "snmp:configured-target", ObservedAt: time.Now().UTC()}
	accepted, unresolved, err := client.Submit(t.Context(), []entity.Observation{claim})
	if err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("delivery discarded a complete receipt after the former five-second deadline", accepted, unresolved, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	if accepted, unresolved, err := client.Submit(ctx, []entity.Observation{claim}); !errors.Is(err, context.DeadlineExceeded) || accepted != 0 || unresolved != 0 {
		t.Fatal("larger delivery budget overrode caller cancellation or invented acceptance", accepted, unresolved, err)
	}
}
