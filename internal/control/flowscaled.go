// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"

// scaledFlowBytes returns the sampling-rate-adjusted byte count for a flow
// record (CORRECT-001). Sampled flow exporters (sFlow, sampled NetFlow/IPFIX)
// observe 1-in-N packets; the raw Bytes counter then UNDERCOUNTS true volume by
// the sampling factor N. The collector records the rate-corrected value in
// BytesScaled. Cost, carbon, NDR-egress, and compliance volume math must read
// the SCALED bytes, or a tenant sampling at rate=64 sees ~1/64th of its real
// traffic and its bills, carbon estimates, and exfil thresholds are all off by
// that factor. When BytesScaled is unset (unsampled exporters leave it 0), the
// raw Bytes already equals true volume, so fall back to it.
func scaledFlowBytes(f *flowv1.FlowRecord) uint64 {
	if s := f.GetBytesScaled(); s != 0 {
		return s
	}
	return f.GetBytes()
}
