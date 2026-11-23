// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package path

// MPLSInference identifies a retained adjacency with increasing quoted
// IPv4 TTLs consistent with label switching without RFC 4950 extensions.
type MPLSInference struct {
	Link
	FromQuotedTTL uint8  `json:"from_quoted_ttl"`
	ToQuotedTTL   uint8  `json:"to_quoted_ttl"`
	Method        string `json:"method"`
}

// InferMPLS uses the qTTL indicator described in "Let There Be Light:
// Revealing Hidden MPLS Tunnels with TNT". A repeated pattern on one observed
// adjacency supports a hypothesis. The inferred adjacency supplies no hidden
// router identities, label values, or tunnel length.
func InferMPLS(p *Path) []MPLSInference {
	if p == nil || p.MeasurementFidelity == nil || p.MeasurementFidelity.AcquisitionMode != "raw_icmp" ||
		p.MeasurementFidelity.HopVisibility != "full" {
		return nil
	}
	byTTL := make(map[int]HopNode, len(p.Hops))
	for _, hop := range p.Hops {
		if len(hop.Nodes) == 1 {
			node := hop.Nodes[0]
			if len(node.MPLS) == 0 && node.Received > 0 && node.QuotedTTL > 1 && int(node.QuotedTTL) <= hop.TTL {
				byTTL[hop.TTL] = node
			}
		}
	}
	var inferred []MPLSInference
	for _, link := range p.Links {
		from, fromOK := byTTL[link.TTL]
		to, toOK := byTTL[link.TTL+1]
		if fromOK && toOK && from.IP == link.From && to.IP == link.To && from.IP != to.IP && int(to.QuotedTTL) == int(from.QuotedTTL)+1 {
			inferred = append(inferred, MPLSInference{Link: link, FromQuotedTTL: from.QuotedTTL, ToQuotedTTL: to.QuotedTTL, Method: "quoted_ttl"})
		}
	}
	return inferred
}
