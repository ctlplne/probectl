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

func encodeProbeOutcome(m *entity.ProbeOutcome) *agentv1.ProbeOutcome {
	if m == nil {
		return nil
	}
	out := &agentv1.ProbeOutcome{Version: uint32(m.Version), DefinitionHash: m.DefinitionHash, CanaryType: m.CanaryType, StartedUnixNanos: m.StartedAt.UnixNano(), CompletedUnixNanos: m.CompletedAt.UnixNano(), Success: m.Success, Canceled: m.Canceled}
	if m.HTTPResponse != nil {
		out.HttpResponse = &agentv1.ProbeHttpResponse{StatusCode: uint32(m.HTTPResponse.StatusCode), TlsVerified: m.HTTPResponse.TLSVerified, SameOrigin: m.HTTPResponse.SameOrigin}
	}
	return out
}

// Every accepted typed observation needs its own retained-family receipt.
// A legacy generic ack, unknown extension or unrelated plane cannot discard
// metadata while acknowledging success. Explicitly unresolved sources remain
// unresolved; the count never upgrades them into retained observations.
func validICMPEvidenceReceipt(request *agentv1.SubmitEntityEvidenceRequest, response *agentv1.SubmitEntityEvidenceResponse) bool {
	if request == nil || response == nil || len(response.ProtoReflect().GetUnknown()) != 0 || response.GetFaultsPersisted() != 0 || response.GetRouting() != nil || response.GetRoutingMessage() != nil || hasPublicRoutingReceipt(response) || response.GetFlowRouting() != nil || response.GetDeviceCounter() != nil {
		return false
	}
	var icmp, outcomes uint32
	for _, observation := range request.Observations {
		if observation == nil || observation.GetIcmp() != nil && observation.GetProbeOutcome() != nil {
			return false
		}
		if observation.GetIcmp() != nil {
			icmp++
		}
		if observation.GetProbeOutcome() != nil {
			outcomes++
		}
	}
	total := uint32(len(request.Observations))
	accepted, unresolved := response.GetAccepted(), response.GetUnresolved()
	retainedICMP, retainedOutcomes := response.GetIcmpMeasurementsPersisted(), response.GetProbeOutcomesPersisted()
	if accepted > total || unresolved != total-accepted || retainedICMP > icmp || retainedOutcomes > outcomes {
		return false
	}
	retained := retainedICMP + retainedOutcomes
	return retained <= accepted && accepted-retained <= total-icmp-outcomes && icmp+outcomes-retained <= unresolved
}
