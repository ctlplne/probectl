// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"

// One authenticated evidence operation may select one plane only. Unknown
// fields cannot turn an unsupported operation into a partial accepted write.
func validEntityEvidenceEnvelope(req *agentv1.SubmitEntityEvidenceRequest) bool {
	if req == nil || len(req.ProtoReflect().GetUnknown()) != 0 {
		return false
	}
	count := 0
	for _, present := range []bool{len(req.Observations)+len(req.Faults) > 0, req.FlowRouting != nil, req.RoutingPeerUp != nil, req.RoutingMessage != nil, req.PublicRoutingPeerTable != nil, req.PublicRoutingMessage != nil, req.DeviceCounter != nil, req.BmpPeerSessions != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return false
	}
	if req.BmpPeerSessions != nil {
		return validBMPPeerSessionEnvelope(req.BmpPeerSessions)
	}
	for _, item := range req.Observations {
		if item.GetBmpPeerSession() != nil {
			return false
		}
	}
	return true
}

func validBMPPeerSessionEnvelope(batch *agentv1.BmpPeerSessionBatch) bool {
	if batch == nil || len(batch.ProtoReflect().GetUnknown()) != 0 || len(batch.Observations) == 0 || len(batch.Observations) > 64 {
		return false
	}
	typed := false
	for _, item := range batch.Observations {
		if item == nil || len(item.ProtoReflect().GetUnknown()) != 0 || item.SourceKind != "bmp_peer" || item.Icmp != nil || item.ProbeOutcome != nil || item.SnmpInterfaceState != nil {
			return false
		}
		typed = typed || item.BmpPeerSession != nil
	}
	return typed
}
