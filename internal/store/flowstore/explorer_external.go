// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/ctlplne/probectl/internal/flow"
)

type explorerExternalKind uint8

const (
	externalTagLookup explorerExternalKind = iota + 1
	externalTagPrefixes
	externalInterfaceRoles
	externalRoutingReferences
	externalRoutingFacts
	externalPeeringInterfaces
	externalPeeringCaptures
)

type explorerExternalData struct {
	kind explorerExternalKind
	rows []byte
}

// Kinds select fixed code-owned identifiers/schemas. Neither query grammar
// nor metadata values can choose an external table name or SQL structure.
func (data explorerExternalData) specification() (string, string, error) {
	switch data.kind {
	case externalTagLookup:
		return "tag_lookup", "lookup_tenant String, lookup_exporter String, lookup_context String, tag_values Map(String, String)", nil
	case externalTagPrefixes:
		return "tag_prefix_lookup", "prefix_tenant String, prefix_context String, prefix_family UInt8, prefix_start UInt128, prefix_end UInt128, prefix_values Map(String, String), prefix_present UInt8", nil
	case externalInterfaceRoles:
		return "interface_role_lookup", "role_tenant String, role_exporter String, role_protocol String, role_domain UInt32, role_index UInt32, role_value String", nil
	case externalRoutingReferences:
		return "routing_capture_lookup", "routing_ref_tenant String, routing_key String, routing_clock Int64, routing_fact String", nil
	case externalRoutingFacts:
		return "routing_fact_lookup", "routing_fact_tenant String, routing_fact_id String, routing_values Map(String, String)", nil
	case externalPeeringInterfaces:
		return "peering_interface_lookup", "peer_tenant String, peer_exporter String, peer_protocol String, peer_domain UInt32, peer_index UInt32, peer_interface String, peer_role String", nil
	case externalPeeringCaptures:
		return "peering_capture_lookup", "peer_capture_tenant String, peer_key String, peer_clock Int64, peer_state String", nil
	default:
		return "", "", ErrTagQueryScope
	}
}

func planTagPrefixSides(plan flow.QueryPlan) []string {
	names := append(append(append([]string{}, plan.GroupBy...), plan.MatrixWith...), flow.QueryFilterFields(plan.Filter)...)
	var sides []string
	for _, side := range []string{"src_prefix", "dst_prefix"} {
		for _, name := range names {
			if strings.HasPrefix(name, "tag."+side+".") {
				sides = append(sides, side)
				break
			}
		}
	}
	return sides
}

func (d *TagQueryData) externalData(ctx context.Context, tenant string, plan flow.QueryPlan, maxBytes int64) ([]explorerExternalData, error) {
	root, err := d.ExternalRows(tenant, maxBytes, ctx)
	if err != nil {
		return nil, err
	}
	result := []explorerExternalData{{kind: externalTagLookup, rows: root}}
	if len(planTagPrefixSides(plan)) > 0 {
		prefixes, err := d.externalPrefixRows(ctx, tenant, maxBytes-int64(len(root)))
		if err != nil {
			return nil, err
		}
		result = append(result, explorerExternalData{kind: externalTagPrefixes, rows: prefixes})
	}
	return result, nil
}

func (d *TagQueryData) externalPrefixRows(ctx context.Context, tenant string, maxBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := d.Revision(tenant); err != nil {
		return nil, err
	}
	if maxBytes < 0 {
		return nil, ErrExplorerBudget
	}
	groups := make([]tagPrefixGroup, 0, len(d.prefixes))
	for group := range d.prefixes {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].contextID != groups[j].contextID {
			return groups[i].contextID < groups[j].contextID
		}
		return groups[i].family < groups[j].family
	})
	var body bytes.Buffer
	for _, group := range groups {
		for _, span := range d.prefixes[group] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			values := span.values
			if values == nil {
				values = map[string]string{}
			}
			row, err := json.Marshal(struct {
				Tenant  string            `json:"prefix_tenant"`
				Context string            `json:"prefix_context"`
				Family  uint8             `json:"prefix_family"`
				Start   json.RawMessage   `json:"prefix_start"`
				End     json.RawMessage   `json:"prefix_end"`
				Values  map[string]string `json:"prefix_values"`
				Present uint8             `json:"prefix_present"`
			}{tenant, group.contextID, group.family, span.start.decimal(), span.end.decimal(), values, 1})
			if err != nil {
				return nil, err
			}
			if int64(body.Len()+len(row)+1) > maxBytes {
				return nil, ErrExplorerBudget
			}
			body.Write(row)
			body.WriteByte('\n')
		}
	}
	return body.Bytes(), nil
}

func prefixTagColumn(side string) string {
	if side == "src_prefix" {
		return "src_addr"
	}
	if side == "dst_prefix" {
		return "dst_addr"
	}
	return ""
}

func prefixTagAddressSQL(column string) (string, string) {
	address := explorerAddressExpr(column)
	family := "if(position(" + column + ",'%')>0,toUInt8(0),multiIf(isIPv4String(" + address + "),toUInt8(4),isIPv6String(" + address + "),toUInt8(6),toUInt8(0)))"
	number := "if(isIPv4String(" + address + "),toUInt128(IPv4StringToNumOrDefault(" + address + ")),reinterpretAsUInt128(reverse(IPv6StringToNumOrDefault(" + address + "))))"
	return family, number
}

func prefixTagFamilyColumn(side string) string {
	return "__probectl_" + side + "_family"
}

func prefixTagPointColumn(side string) string {
	return "__probectl_" + side + "_point"
}

func prefixTagJoinSQL(side string) string {
	alias := side + "_tags"
	return " ASOF LEFT JOIN tag_prefix_lookup AS " + alias + " ON tenant_id=" + alias + ".prefix_tenant AND tag_lookup.lookup_context=" + alias + ".prefix_context AND " + prefixTagFamilyColumn(side) + "=" + alias + ".prefix_family AND " + prefixTagPointColumn(side) + ">=" + alias + ".prefix_start"
}

func prefixTagValuesSQL(side string) string {
	alias := side + "_tags"
	return "if(" + alias + ".prefix_present=1 AND " + prefixTagPointColumn(side) + "<=" + alias + ".prefix_end," + alias + ".prefix_values,CAST(map(),'Map(String,String)'))"
}

func prefixTagValueSQL(side, name string) string {
	return "ifNull(__probectl_" + side + "_values[{" + name + ":String}],'')"
}

// Resolve interval validity once per side, then share the bounded map among
// every selected/filter key. Physical flow columns keep their original names;
// repeated columns from the two external joins never escape this projection.
func prefixTagProjectionSQL(from string, sides []string) string {
	if len(sides) == 0 {
		return from
	}
	fields := []string{"flow_input.*", "tag_lookup.tag_values AS tag_values"}
	for _, side := range sides {
		fields = append(fields, prefixTagValuesSQL(side)+" AS __probectl_"+side+"_values")
	}
	return "(SELECT " + strings.Join(fields, ",") + " FROM " + from + ") AS flow_tags"
}
