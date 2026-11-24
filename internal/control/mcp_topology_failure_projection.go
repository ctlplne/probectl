// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/flow"
)

type nativeFailurePort struct {
	flow.FailurePort
	InterfaceID mcp.NativeRoleUUID `json:"interface_id"`
}

type nativeFailureLoad struct {
	flow.FailureTrafficPortProjection
	InterfaceID      mcp.NativeRoleUUID       `json:"interface_id"`
	CapacityBPS      mcp.NativePeeringCounter `json:"capacity_bps,omitempty"`
	MeasuredBPS      nativeMeasurementRatio   `json:"measured_bps,omitempty"`
	AddedBPS         nativeMeasurementRatio   `json:"added_bps"`
	RemovedBPS       nativeMeasurementRatio   `json:"removed_bps"`
	ProjectedBPS     nativeMeasurementRatio   `json:"projected_bps,omitempty"`
	UtilizationRatio nativeMeasurementRatio   `json:"utilization_ratio,omitempty"`
}

type nativeFailurePeak struct {
	flow.FailureTrafficPeak
	BPS nativeMeasurementRatio `json:"bps"`
}

type nativeFailureLastSample struct {
	flow.CapacityForecastObservedSample
	BPS         nativeMeasurementRatio `json:"bps"`
	Utilization nativeMeasurementRatio `json:"utilization"`
}

type nativeFailureRunout struct {
	flow.CapacityForecastResult
	Target              mcp.NativeRoleUUID       `json:"target"`
	CapacityNumerator   mcp.NativePeeringCounter `json:"capacity_numerator"`
	CapacityDenominator mcp.NativePeeringCounter `json:"capacity_denominator"`
	TrendNumerator      nativeSignedDecimal      `json:"trend_bps_per_day_numerator,omitempty"`
	TrendDenominator    mcp.NativePeeringCounter `json:"trend_bps_per_day_denominator,omitempty"`
	LastSample          *nativeFailureLastSample `json:"last_sample,omitempty"`
}

type nativeFailurePortSeries struct {
	flow.FailureTrafficPortSeries
	InterfaceID   mcp.NativeRoleUUID   `json:"interface_id"`
	Current       nativeFailureLoad    `json:"current"`
	MeasuredPeak  *nativeFailurePeak   `json:"measured_peak,omitempty"`
	ProjectedPeak *nativeFailurePeak   `json:"projected_peak,omitempty"`
	Runout        *nativeFailureRunout `json:"runout,omitempty"`
}

type nativeFailureSeries struct {
	flow.FailureTrafficSeries
	AffectedBytes   nativeMeasurementRatio    `json:"affected_bytes"`
	ReroutedBytes   nativeMeasurementRatio    `json:"rerouted_bytes"`
	UnroutedBytes   nativeMeasurementRatio    `json:"unrouted_bytes"`
	UnresolvedBytes nativeMeasurementRatio    `json:"unresolved_bytes"`
	Ports           []nativeFailurePortSeries `json:"ports"`
}

// Only validated IDs and computed numbers need transport encoding. Graph
// strings and other human-readable fields remain subject to tenant redaction.
func marshalNativeTopologyFailure(result whatIfResponse) (json.RawMessage, error) {
	traffic := result.Traffic
	native := struct {
		whatIfResponse
		Traffic struct {
			topologyFailureTraffic
			ContextID   mcp.NativeRoleUUID   `json:"context_id"`
			FailedPorts []nativeFailurePort  `json:"failed_ports"`
			Projection  *nativeFailureSeries `json:"projection,omitempty"`
		} `json:"traffic"`
	}{whatIfResponse: result}
	native.Traffic.topologyFailureTraffic = *traffic
	native.Traffic.ContextID = mcp.NativeRoleUUID(traffic.ContextID)
	native.Traffic.FailedPorts = make([]nativeFailurePort, 0, len(traffic.FailedPorts))
	for _, port := range traffic.FailedPorts {
		native.Traffic.FailedPorts = append(native.Traffic.FailedPorts, nativeFailurePort{port, mcp.NativeRoleUUID(port.InterfaceID)})
	}
	if series := traffic.Projection; series != nil {
		out := &nativeFailureSeries{FailureTrafficSeries: *series, AffectedBytes: nativeMeasurementRatio(series.AffectedBytes),
			ReroutedBytes: nativeMeasurementRatio(series.ReroutedBytes), UnroutedBytes: nativeMeasurementRatio(series.UnroutedBytes),
			UnresolvedBytes: nativeMeasurementRatio(series.UnresolvedBytes), Ports: make([]nativeFailurePortSeries, 0, len(series.Ports))}
		for _, port := range series.Ports {
			current := port.Current
			out.Ports = append(out.Ports, nativeFailurePortSeries{
				FailureTrafficPortSeries: port, InterfaceID: mcp.NativeRoleUUID(port.InterfaceID),
				Current: nativeFailureLoad{FailureTrafficPortProjection: current, InterfaceID: mcp.NativeRoleUUID(current.InterfaceID),
					CapacityBPS: mcp.NativePeeringCounter(current.CapacityBPS), MeasuredBPS: nativeMeasurementRatio(current.MeasuredBPS),
					AddedBPS: nativeMeasurementRatio(current.AddedBPS), RemovedBPS: nativeMeasurementRatio(current.RemovedBPS),
					ProjectedBPS: nativeMeasurementRatio(current.ProjectedBPS), UtilizationRatio: nativeMeasurementRatio(current.UtilizationRatio)},
				MeasuredPeak: nativeTopologyFailurePeak(port.MeasuredPeak), ProjectedPeak: nativeTopologyFailurePeak(port.ProjectedPeak),
				Runout: nativeTopologyFailureRunout(port.Runout),
			})
		}
		native.Traffic.Projection = out
	}
	return json.Marshal(native)
}

func nativeTopologyFailurePeak(peak *flow.FailureTrafficPeak) *nativeFailurePeak {
	if peak == nil {
		return nil
	}
	return &nativeFailurePeak{*peak, nativeMeasurementRatio(peak.BPS)}
}

func nativeTopologyFailureRunout(runout *flow.CapacityForecastResult) *nativeFailureRunout {
	if runout == nil {
		return nil
	}
	out := &nativeFailureRunout{CapacityForecastResult: *runout, Target: mcp.NativeRoleUUID(runout.Target),
		CapacityNumerator: mcp.NativePeeringCounter(runout.CapacityNumerator), CapacityDenominator: mcp.NativePeeringCounter(runout.CapacityDenominator),
		TrendNumerator: nativeSignedDecimal(runout.TrendNumerator), TrendDenominator: mcp.NativePeeringCounter(runout.TrendDenominator)}
	if sample := runout.LastSample; sample != nil {
		out.LastSample = &nativeFailureLastSample{*sample, nativeMeasurementRatio(sample.BPS), nativeMeasurementRatio(sample.Utilization)}
	}
	return out
}
