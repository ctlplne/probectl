// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestCounterWitnessReceiverKeepsWholePollAndCertifiedTenantOnly(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	id := crypto.SPIFFEID{TrustDomain: crypto.TrustDomain, Plane: "entity", TenantID: tenant, AgentID: "same-agent"}
	req := &agentv1.SubmitEntityEvidenceRequest{DeviceCounter: &agentv1.DeviceCounterWitness{ContractVersion: "device_counter_capture_v1", ConfiguredRef: "192.0.2.1", RawDigest: make([]byte, 32), PollStartedUnixNanos: 1794000000123456789, PollCompletedUnixNanos: 1794000001987654321, PointCount: 5001}}
	req.DeviceCounter.RawDigest[31] = 255
	var keys [2][32]byte
	for lane, tenant := range []string{tenant, "66666666-6666-4666-8666-666666666666"} {
		id.TenantID = tenant
		digest, input, err := parseCounterWitness(id, req)
		if err != nil || input.PointCount != 5001 || input.PollStartedAt.UnixNano() != req.DeviceCounter.PollStartedUnixNanos || input.PollCompletedAt.UnixNano() != req.DeviceCounter.PollCompletedUnixNanos || digest[31] != 255 {
			t.Fatal("receiver changed original complete counter witness", err)
		}
		keys[lane], err = entity.CounterCaptureKey(tenant, id.AgentID, digest, input)
		if err != nil {
			t.Fatal(err)
		}
	}
	if keys[0] == keys[1] {
		t.Fatal("counter receiver crossed certificate tenant scope")
	}
	id.TenantID = tenant
	for _, mutate := range []func(*agentv1.SubmitEntityEvidenceRequest){
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.DeviceCounter.ContractVersion = "future" },
		func(r *agentv1.SubmitEntityEvidenceRequest) {
			r.DeviceCounter.RawDigest = r.DeviceCounter.RawDigest[:31]
		},
		func(r *agentv1.SubmitEntityEvidenceRequest) { clear(r.DeviceCounter.RawDigest) },
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.DeviceCounter.PointCount = 0 },
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.DeviceCounter.ConfiguredRef = "" },
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.DeviceCounter.PollStartedUnixNanos = 0 },
		func(r *agentv1.SubmitEntityEvidenceRequest) {
			r.DeviceCounter.PollCompletedUnixNanos = r.DeviceCounter.PollStartedUnixNanos - 1
		},
		func(r *agentv1.SubmitEntityEvidenceRequest) {
			r.Observations = []*agentv1.EntityEvidenceObservation{{}}
		},
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.FlowRouting = &agentv1.FlowRoutingWitnessBatch{} },
		func(r *agentv1.SubmitEntityEvidenceRequest) {
			r.DeviceCounter.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
		},
		func(r *agentv1.SubmitEntityEvidenceRequest) { r.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1}) },
	} {
		changed := proto.Clone(req).(*agentv1.SubmitEntityEvidenceRequest)
		mutate(changed)
		digest, input, err := parseCounterWitness(id, changed)
		if err == nil || digest != ([32]byte{}) || input != (entity.CounterCaptureInput{}) {
			t.Fatal("malformed or mixed counter witness was partially accepted")
		}
	}
	for _, changed := range []crypto.SPIFFEID{{TrustDomain: "foreign", Plane: "entity", TenantID: tenant, AgentID: id.AgentID}, {TrustDomain: crypto.TrustDomain, Plane: "agent", TenantID: tenant, AgentID: id.AgentID}, {TrustDomain: crypto.TrustDomain, Plane: "entity", TenantID: "foreign", AgentID: id.AgentID}} {
		if _, _, err := parseCounterWitness(changed, req); err == nil {
			t.Fatal("unverified peer supplied counter sender authority")
		}
	}
}

func TestCounterWitnessStateAdmissionIsIndependentOfRouting(t *testing.T) {
	limits := defaultRoutingTransportLimits()
	original := limits.captureStateBytes
	if err := WithDeviceCounterStateBytes(1 << 40)(&limits); err != nil || limits.counterStateBytes != 1<<40 || limits.captureStateBytes != original {
		t.Fatal("counter state admission changed routing state or refused a raised workload", err)
	}
	for _, bad := range []int64{0, -1} {
		if err := WithDeviceCounterStateBytes(bad)(&limits); err == nil {
			t.Fatal("nonpositive counter state admission was accepted")
		}
	}
}
