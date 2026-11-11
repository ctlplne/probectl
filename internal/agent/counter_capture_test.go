// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestCounterWitnessClientBindsCertificateTenantSenderAndWholeReceipt(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const sender = "same-agent"
	input := entity.CounterCaptureInput{ConfiguredTarget: "192.0.2.1", PollStartedAt: time.Unix(1794000000, 123456789), PollCompletedAt: time.Unix(1794000001, 987654321), PointCount: 5001}
	digest := [32]byte{1, 255}
	key, err := entity.CounterCaptureKey(tenant, sender, digest, input)
	if err != nil {
		t.Fatal(err)
	}
	good := &agentv1.SubmitEntityEvidenceResponse{DeviceCounter: &agentv1.DeviceCounterCapture{Key: append([]byte(nil), key[:]...), CapturedUnixNanos: 1794000002987654321}}
	stub := &routingReceiptClient{response: good}
	client := &EvidenceClient{tenantID: tenant, agentID: sender, svc: stub}
	got, err := client.CaptureCounters(t.Context(), sender, digest, input)
	if err != nil || got.Key != key || got.CapturedAt.UnixNano() != good.DeviceCounter.CapturedUnixNanos {
		t.Fatal("certified counter witness lost its whole digest, clock or identity", err)
	}
	raw := stub.request.GetDeviceCounter()
	if raw == nil || raw.PointCount != 5001 || raw.PollStartedUnixNanos != input.PollStartedAt.UnixNano() || raw.PollCompletedUnixNanos != input.PollCompletedAt.UnixNano() || raw.ConfiguredRef != input.ConfiguredTarget || !validCounterExclusiveRequest(stub.request) {
		t.Fatal("counter witness changed original source or population")
	}
	for _, mutate := range []func(*agentv1.SubmitEntityEvidenceResponse){
		func(r *agentv1.SubmitEntityEvidenceResponse) { r.DeviceCounter = nil },
		func(r *agentv1.SubmitEntityEvidenceResponse) { r.DeviceCounter.Key[0] ^= 255 },
		func(r *agentv1.SubmitEntityEvidenceResponse) { r.DeviceCounter.CapturedUnixNanos = 0 },
		func(r *agentv1.SubmitEntityEvidenceResponse) { r.Accepted = 1 },
		func(r *agentv1.SubmitEntityEvidenceResponse) { r.FlowRouting = &agentv1.FlowRoutingCaptureBatch{} },
		func(r *agentv1.SubmitEntityEvidenceResponse) { r.Routing = &agentv1.BmpRoutingStagingReceipt{} },
		func(r *agentv1.SubmitEntityEvidenceResponse) {
			r.PublicRouting = &agentv1.PublicRoutingStagingReceipt{}
		},
		func(r *agentv1.SubmitEntityEvidenceResponse) { r.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1}) },
		func(r *agentv1.SubmitEntityEvidenceResponse) {
			r.DeviceCounter.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
		},
	} {
		r := proto.Clone(good).(*agentv1.SubmitEntityEvidenceResponse)
		mutate(r)
		stub.response = r
		if got, err := client.CaptureCounters(t.Context(), sender, digest, input); err == nil || got != (entity.CounterCaptureReference{}) {
			t.Fatal("altered or mixed evidence receipt yielded a counter witness")
		}
	}
	stub.response = good
	client.tenantID = "66666666-6666-4666-8666-666666666666"
	if _, err := client.CaptureCounters(t.Context(), sender, digest, input); err == nil {
		t.Fatal("foreign certificate tenant accepted the same counter receipt")
	}
	stub.request = nil
	if _, err := client.CaptureCounters(t.Context(), "spoofed", digest, input); err == nil || stub.request != nil {
		t.Fatal("payload sender replaced this client's certificate identity")
	}
}

func validCounterExclusiveRequest(r *agentv1.SubmitEntityEvidenceRequest) bool {
	return r.GetDeviceCounter() != nil && len(r.GetObservations())+len(r.GetFaults()) == 0 && r.GetRoutingPeerUp() == nil && r.GetRoutingMessage() == nil && r.GetFlowRouting() == nil && r.GetPublicRoutingPeerTable() == nil && r.GetPublicRoutingMessage() == nil
}
