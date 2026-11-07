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
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type evidenceAdapterCapture struct {
	t                *testing.T
	ctx              context.Context
	up               *agentv1.BmpRoutingPeerUp
	message          *agentv1.BmpRoutingMessage
	stage            *agentv1.BmpRoutingStagingReceipt
	receipt          *agentv1.BmpRoutingMessageReceipt
	err              error
	stages, messages int
}

func (c *evidenceAdapterCapture) Submit(context.Context, []entity.Observation) (int, int, error) {
	return 2, 1, c.err
}

func (c *evidenceAdapterCapture) StageRoutingPeer(ctx context.Context, up *agentv1.BmpRoutingPeerUp) (*agentv1.BmpRoutingStagingReceipt, error) {
	c.t.Helper()
	if ctx != c.ctx || up != c.up {
		c.t.Fatal("adapter replaced routing stage context or complete request")
	}
	c.stages++
	return c.stage, c.err
}

func (c *evidenceAdapterCapture) SubmitRoutingMessage(ctx context.Context, message *agentv1.BmpRoutingMessage) (*agentv1.BmpRoutingMessageReceipt, error) {
	c.t.Helper()
	if ctx != c.ctx || message != c.message {
		c.t.Fatal("adapter replaced routing stream context or complete request")
	}
	c.messages++
	return c.receipt, c.err
}

// The command's metrics wrapper must retain the optional routing interfaces.
// The RPC sink is modeled here; actual mTLS has its separate integration proof.
func TestBMPEvidenceAdapterKeepsCompleteRoutingTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	capture := &evidenceAdapterCapture{t: t, ctx: ctx,
		up:      &agentv1.BmpRoutingPeerUp{Message: []byte{1, 2, 3}},
		message: &agentv1.BmpRoutingMessage{Message: []byte{4, 5, 6}, Sequence: 17},
		stage:   &agentv1.BmpRoutingStagingReceipt{Status: "staged"},
		receipt: &agentv1.BmpRoutingMessageReceipt{Status: "applied", Sequence: 17}}
	var adapter any = observedBMPEvidence{client: capture}
	stager, ok := adapter.(interface {
		StageRoutingPeer(context.Context, *agentv1.BmpRoutingPeerUp) (*agentv1.BmpRoutingStagingReceipt, error)
	})
	if !ok {
		t.Fatal("shipped metrics adapter hides routing staging transport")
	}
	writer, ok := adapter.(interface {
		SubmitRoutingMessage(context.Context, *agentv1.BmpRoutingMessage) (*agentv1.BmpRoutingMessageReceipt, error)
	})
	if !ok {
		t.Fatal("shipped metrics adapter hides routing message transport")
	}
	for _, err := range []error{nil, errors.New("evidence unavailable")} {
		capture.err = err
		stage, gotErr := stager.StageRoutingPeer(ctx, capture.up)
		if stage != capture.stage || gotErr != err {
			t.Fatal("adapter altered complete staging receipt or error")
		}
		receipt, gotErr := writer.SubmitRoutingMessage(ctx, capture.message)
		if receipt != capture.receipt || gotErr != err {
			t.Fatal("adapter altered complete stream receipt or error")
		}
	}
	if capture.stages != 2 || capture.messages != 2 {
		t.Fatal("adapter did not forward each routing call exactly once")
	}
}
