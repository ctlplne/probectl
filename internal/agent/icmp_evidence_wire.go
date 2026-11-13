// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"encoding/hex"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func encodeICMPMeasurement(m *entity.ICMPMeasurement) *agentv1.IcmpMeasurement {
	if m == nil {
		return nil
	}
	out := &agentv1.IcmpMeasurement{Version: uint32(m.Version), DefinitionHash: m.DefinitionHash,
		StartedUnixNanos: m.StartedAt.UnixNano(), CompletedUnixNanos: m.CompletedAt.UnixNano(),
		Requested: m.Requested, Attempted: m.Attempted, Transmitted: m.Transmitted,
		Replies: m.Replies, SendErrors: m.SendErrors, ReadComplete: m.ReadComplete,
		Canceled: m.Canceled, IoFailed: m.IOFailed, Responders: append([]string(nil), m.Responders...)}
	for _, item := range m.NetworkErrors {
		digest, _ := hex.DecodeString(item.PacketDigest) // normalized before encoding
		out.NetworkErrors = append(out.NetworkErrors, &agentv1.IcmpNetworkError{Sequence: item.Sequence,
			Responder: item.Responder, Type: item.Type, Code: item.Code, ReceivedUnixNanos: item.ReceivedAt.UnixNano(),
			PacketDigest: digest, Conflicting: item.Conflicting})
	}
	return out
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
	items := request.Observations
	if request.BmpPeerSessions != nil {
		if len(items) != 0 || len(request.BmpPeerSessions.ProtoReflect().GetUnknown()) != 0 {
			return false
		}
		items = request.BmpPeerSessions.Observations
	}
	var icmp, outcomes, states, sessions uint32
	for _, observation := range items {
		if observation == nil {
			return false
		}
		families := 0
		if observation.GetIcmp() != nil {
			icmp++
			families++
		}
		if observation.GetProbeOutcome() != nil {
			outcomes++
			families++
		}
		if observation.GetSnmpInterfaceState() != nil {
			states++
			families++
		}
		if observation.GetBmpPeerSession() != nil {
			sessions++
			families++
		}
		if families > 1 {
			return false
		}
	}
	if sessions > 0 && request.BmpPeerSessions == nil {
		return false
	}
	total := uint32(len(items))
	accepted, unresolved := response.GetAccepted(), response.GetUnresolved()
	retainedICMP, retainedOutcomes := response.GetIcmpMeasurementsPersisted(), response.GetProbeOutcomesPersisted()
	retainedStates := response.GetInterfaceStatesPersisted()
	retainedSessions := response.GetBmpPeerSessionsPersisted()
	if accepted > total || unresolved != total-accepted || retainedICMP > icmp || retainedOutcomes > outcomes || retainedStates > states || retainedSessions > sessions {
		return false
	}
	retained := retainedICMP + retainedOutcomes + retainedStates + retainedSessions
	return retained <= accepted && accepted-retained <= total-icmp-outcomes-states-sessions && icmp+outcomes+states+sessions-retained <= unresolved
}

func encodeBMPPeerSession(m *entity.BMPPeerSession) *agentv1.BmpPeerSession {
	if m == nil {
		return nil
	}
	return &agentv1.BmpPeerSession{Frame: append([]byte(nil), m.RawFrame...)}
}
