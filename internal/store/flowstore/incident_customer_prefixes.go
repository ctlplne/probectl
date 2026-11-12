// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"net/netip"
	"sort"
)

type IncidentCustomerPrefix struct {
	ContextID, PrefixID, Prefix, Key, Value string
}

// IncidentCustomerPrefixes uses the SAME compiled closest-subject ranges as
// Explorer. Empty/ambiguous winners block broader labels. The original flow
// owner must agree with the current exporter context before metadata enters
// a result. Source/destination matches are a union, not multiplying joins.
func (d *TagQueryData) IncidentCustomerPrefixes(row Row, ownerContext, key string) ([]IncidentCustomerPrefix, error) {
	if _, err := d.Revision(row.TenantID); err != nil {
		return nil, err
	}
	field, found := d.vocabulary.Lookup("tag.src_prefix." + key)
	if !found || field.TagKey != "src_prefix."+key || d.exporterContexts[row.Exporter] != ownerContext || ownerContext == "" {
		return nil, ErrTagQueryScope
	}
	out := []IncidentCustomerPrefix{}
	for _, raw := range []string{row.SrcAddr, row.DstAddr} {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, errIncidentTrafficRow
		}
		point, family, ok := tagPrefixAddress(address.Unmap())
		if !ok {
			return nil, errIncidentTrafficRow
		}
		ranges := d.prefixes[tagPrefixGroup{ownerContext, family}]
		i := sort.Search(len(ranges), func(i int) bool { return ranges[i].start.compare(point) > 0 }) - 1
		if i < 0 || ranges[i].end.compare(point) < 0 || ranges[i].winner == nil || ranges[i].winner.subjectID == "" || ranges[i].values[key] == "" {
			continue
		}
		winner := ranges[i].winner
		item := IncidentCustomerPrefix{ownerContext, winner.subjectID, winner.network.String(), key, ranges[i].values[key]}
		if len(out) == 0 || out[0] != item {
			out = append(out, item)
		}
	}
	return out, nil
}
