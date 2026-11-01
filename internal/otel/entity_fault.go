// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otel

import "github.com/ctlplne/probectl/internal/entity"

func init() {
	for _, key := range []string{entity.AttrFaultObservationID, entity.AttrFaultKind,
		entity.AttrSourceKind} {
		KnownAttributes[key] = true
	}
}

// EntityFaultAttributes maps a validated evidence-plane fault at its first
// emission. Tenant and agent come from the live mTLS peer; the source family
// decides which existing OTel semantic address key describes the target.
// These values are incident evidence, never Prometheus metric labels.
func EntityFaultAttributes(tenantID, agentID string, fault entity.FaultObservation) map[string]string {
	attrs := map[string]string{
		AttrTenantID: tenantID, AttrAgentID: agentID,
		entity.AttrFaultObservationID: fault.ID,
		entity.AttrFaultKind:          string(fault.Kind),
		entity.AttrSourceKind:         string(fault.Source.Kind),
	}
	switch fault.Kind {
	case entity.FaultDevicePollFailed:
		attrs[AttrDeviceAddress] = fault.Target
		attrs[AttrDeviceSource] = "snmp"
	case entity.FaultFlowExporterSilent:
		attrs[AttrFlowExporter] = fault.Target
	}
	return attrs
}
