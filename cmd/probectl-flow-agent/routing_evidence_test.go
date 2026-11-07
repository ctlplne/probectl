// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type routingEvidenceClient struct {
	ctx       context.Context
	witnesses []*agentv1.FlowRoutingWitness
	refs      []*agentv1.FlowRoutingCapture
	err       error
}

func (*routingEvidenceClient) Submit(context.Context, []entity.Observation) (int, int, error) {
	return 0, 0, errors.New("unexpected identity RPC")
}

func (*routingEvidenceClient) SubmitFaults(context.Context, []entity.FaultObservation) (int, error) {
	return 0, errors.New("unexpected fault RPC")
}

func (c *routingEvidenceClient) SubmitFlowRouting(ctx context.Context, witnesses []*agentv1.FlowRoutingWitness) ([]*agentv1.FlowRoutingCapture, error) {
	c.ctx, c.witnesses = ctx, witnesses
	return c.refs, c.err
}

func TestObservedFlowEvidenceKeepsCompleteRoutingWitnessChannel(t *testing.T) {
	client := &routingEvidenceClient{refs: make([]*agentv1.FlowRoutingCapture, 1001)}
	emitter, ok := any(observedFlowEvidence{client: client}).(flow.RoutingWitnessEmitter)
	if !ok {
		t.Fatal("runtime evidence wrapper dropped the routing witness channel")
	}
	witnesses := make([]*agentv1.FlowRoutingWitness, 1001)
	for i := range witnesses {
		witnesses[i] = &agentv1.FlowRoutingWitness{ObservationDomain: uint32(i)}
		client.refs[i] = &agentv1.FlowRoutingCapture{CapturedUnixNanos: int64(i + 1)}
	}
	refs, err := emitter.SubmitFlowRouting(t.Context(), witnesses)
	if err != nil || len(refs) != len(witnesses) || client.ctx != t.Context() || len(client.witnesses) != len(witnesses) {
		t.Fatal("runtime evidence wrapper lost the complete configured batch or context", err)
	}
	for i := range witnesses {
		if client.witnesses[i] != witnesses[i] || refs[i] != client.refs[i] {
			t.Fatal("runtime evidence wrapper changed ordered original witnesses or receipts", i)
		}
	}
	client.refs, client.err = nil, errors.New("restricted sender authentication refused")
	if refs, err := emitter.SubmitFlowRouting(t.Context(), witnesses); refs != nil || !errors.Is(err, client.err) {
		t.Fatal("runtime evidence wrapper hid sender refusal")
	}
}
