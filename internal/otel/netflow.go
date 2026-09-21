// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otel

import (
	"strconv"

	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
)

// Device-flow attribute keys (S38). The 5-tuple reuses the OTel source.* /
// destination.* / network.* conventions already registered by the eBPF flow
// mapping; AS/geo enrichment uses the ECS-aligned source.as.* / *.geo.* names
// (no OTel convention exists for them — no invented names where a standard,
// OTel or ECS, already does the job); exporter/protocol/interface/sampling
// detail has no standard home and uses the probectl.flow.* namespace.
const (
	AttrFlowExporter     = "probectl.flow.exporter.address"
	AttrFlowProtocol     = "probectl.flow.protocol"
	AttrFlowIfIn         = "probectl.flow.interface.in"
	AttrFlowIfOut        = "probectl.flow.interface.out"
	AttrFlowSamplingRate = "probectl.flow.sampling.rate"

	AttrSourceASNumber   = "source.as.number"
	AttrSourceASOrg      = "source.as.organization.name"
	AttrSourceGeoCountry = "source.geo.country.iso_code"
	AttrDestASNumber     = "destination.as.number"
	AttrDestASOrg        = "destination.as.organization.name"
	AttrDestGeoCountry   = "destination.geo.country.iso_code"
)

// Register the device-flow keys into the shared conformance set (the S6
// "no invented names" bar, enforced by TestAllSignalMappingsConform).
func init() {
	for _, k := range []string{
		AttrFlowExporter, AttrFlowProtocol, AttrFlowIfIn, AttrFlowIfOut, AttrFlowSamplingRate,
		AttrSourceASNumber, AttrSourceASOrg, AttrSourceGeoCountry,
		AttrDestASNumber, AttrDestASOrg, AttrDestGeoCountry,
	} {
		KnownAttributes[k] = true
	}
}

// netFlowAttributes maps a device FlowRecord (NetFlow/IPFIX/sFlow) to its OTel
// resource + network attributes — designed in at the schema (CONTRIBUTING.md), so
// the OTLP layer (S22) exposes rather than remaps. The tenant is the outermost
// scope; zero/empty optionals are omitted.
func netFlowAttributes(f *flowv1.FlowRecord) map[string]string {
	attrs := map[string]string{
		AttrTenantID: f.GetTenantId(),
	}
	put := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	putU := func(k string, v uint64) {
		if v != 0 {
			attrs[k] = strconv.FormatUint(v, 10)
		}
	}
	put(AttrAgentID, f.GetAgentId())
	put(AttrFlowExporter, f.GetExporterAddress())
	put(AttrFlowProtocol, f.GetFlowProtocol())
	put(AttrSourceAddress, f.GetSourceAddress())
	putU(AttrSourcePort, uint64(f.GetSourcePort()))
	put(AttrDestinationAddress, f.GetDestinationAddress())
	putU(AttrDestinationPort, uint64(f.GetDestinationPort()))
	put(AttrNetworkTransport, f.GetNetworkTransport())
	put(AttrNetworkType, f.GetNetworkType())
	putU(AttrFlowIfIn, uint64(f.GetInputInterface()))
	putU(AttrFlowIfOut, uint64(f.GetOutputInterface()))
	putU(AttrFlowSamplingRate, f.GetSamplingRate())
	putU(AttrSourceASNumber, uint64(f.GetSourceAsn()))
	put(AttrSourceASOrg, f.GetSourceAsName())
	put(AttrSourceGeoCountry, f.GetSourceCountry())
	putU(AttrDestASNumber, uint64(f.GetDestinationAsn()))
	put(AttrDestASOrg, f.GetDestinationAsName())
	put(AttrDestGeoCountry, f.GetDestinationCountry())
	return attrs
}
