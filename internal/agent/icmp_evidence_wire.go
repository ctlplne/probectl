// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func encodeICMPMeasurement(m *entity.ICMPMeasurement) *agentv1.IcmpMeasurement {
	if m == nil {
		return nil
	}
	return &agentv1.IcmpMeasurement{Version: uint32(m.Version), DefinitionHash: m.DefinitionHash,
		StartedUnixNanos: m.StartedAt.UnixNano(), CompletedUnixNanos: m.CompletedAt.UnixNano(),
		Requested: m.Requested, Attempted: m.Attempted, Transmitted: m.Transmitted,
		Replies: m.Replies, SendErrors: m.SendErrors, ReadComplete: m.ReadComplete,
		Canceled: m.Canceled, IoFailed: m.IOFailed, Responders: append([]string(nil), m.Responders...)}
}

// A legacy server can accept the address and discard an unknown metadata
// field. Require a typed receipt, complete counts and no unrelated plane before
// acknowledging ICMP evidence; an omitted receipt is not a partial success.
func validICMPEvidenceReceipt(request *agentv1.SubmitEntityEvidenceRequest, response *agentv1.SubmitEntityEvidenceResponse) bool {
	measurements := uint32(0)
	for _, observation := range request.Observations {
		if observation.GetIcmp() != nil {
			measurements++
		}
	}
	if measurements == 0 {
		return response.GetIcmpMeasurementsPersisted() == 0
	}
	if response == nil || len(response.ProtoReflect().GetUnknown()) != 0 ||
		response.GetFaultsPersisted() != 0 || response.GetRouting() != nil || response.GetRoutingMessage() != nil ||
		hasPublicRoutingReceipt(response) || response.GetFlowRouting() != nil || response.GetDeviceCounter() != nil {
		return false
	}
	total := uint32(len(request.Observations))
	accepted, unresolved, retained := response.GetAccepted(), response.GetUnresolved(), response.GetIcmpMeasurementsPersisted()
	return accepted <= total && unresolved == total-accepted && retained <= accepted && retained <= measurements &&
		accepted-retained <= total-measurements && measurements-retained <= unresolved
}
