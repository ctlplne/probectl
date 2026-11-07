// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

// RoutingQueryField identifies only code-owned routing dimensions. It grants
// no source access; storage requires the independent current tenant projection.
func RoutingQueryField(name string) (QueryField, bool) {
	for _, side := range []string{"src", "dst"} {
		for _, definition := range []struct {
			suffix string
			kind   QueryFieldType
		}{
			{"bgp_provenance", QueryText},
			{"bgp_prefix", QueryText},
			{"bgp_as_paths", QueryText},
			{"bgp_next_hop_as", QueryUnsigned},
			{"bgp_origin_as", QueryUnsigned},
			{"bgp_first_transit_as", QueryUnsigned},
			{"bgp_rpki", QueryText},
		} {
			if name == side+"_"+definition.suffix {
				maximum := uint64(0)
				if definition.kind == QueryUnsigned {
					maximum = 1<<32 - 1
				}
				field := queryField(name, "routing_capture_key", definition.kind, false, maximum)
				field.Derived, field.Permission = "flow_routing", "entities.read"
				return field, true
			}
		}
	}
	return QueryField{}, false
}

func registerRoutingQueryFields() {
	for _, side := range []string{"src", "dst"} {
		for _, suffix := range []string{"bgp_provenance", "bgp_prefix", "bgp_as_paths", "bgp_next_hop_as", "bgp_origin_as", "bgp_first_transit_as", "bgp_rpki"} {
			field, _ := RoutingQueryField(side + "_" + suffix)
			queryFieldRegistry = append(queryFieldRegistry, field)
		}
	}
}
