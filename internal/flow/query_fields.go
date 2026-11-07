// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import "strings"

// QueryFieldType determines the accepted values and operators of a flow facet.
type QueryFieldType string

const (
	QueryText      QueryFieldType = "text"
	QueryAddress   QueryFieldType = "address"
	QueryPrefix    QueryFieldType = "prefix"
	QueryUnsigned  QueryFieldType = "unsigned"
	QueryTimestamp QueryFieldType = "timestamp"
	QueryFlags     QueryFieldType = "flags"
)

// QueryOperator is a structured predicate, never a fragment of SQL.
type QueryOperator string

const (
	QueryEqual       QueryOperator = "eq"
	QueryNotEqual    QueryOperator = "ne"
	QueryIn          QueryOperator = "in"
	QueryNotIn       QueryOperator = "not_in"
	QueryCIDR        QueryOperator = "cidr"
	QueryNotCIDR     QueryOperator = "not_cidr"
	QueryBetween     QueryOperator = "between"
	QueryNotBetween  QueryOperator = "not_between"
	QueryHasAnyFlag  QueryOperator = "has_any"
	QueryHasNoFlag   QueryOperator = "has_none"
	QueryContains    QueryOperator = "contains"
	QueryNotContains QueryOperator = "not_contains"
	QueryRegex       QueryOperator = "regex"
	QueryNotRegex    QueryOperator = "not_regex"
	QueryGreater     QueryOperator = "gt"
	QueryLess        QueryOperator = "lt"
	QueryBitAnd      QueryOperator = "bit_and"
)

// QueryField is shared by storage, Explorer, CLI and MCP. Physical column and
// derivation identifiers stay inside the server. Tenant is deliberately absent.
type QueryField struct {
	Name         string          `json:"name"`
	Type         QueryFieldType  `json:"type"`
	Operators    []QueryOperator `json:"operators"`
	LegacyHourly bool            `json:"legacy_hourly_available"`
	Raw          bool            `json:"raw_available"`
	Rollup       bool            `json:"rollup_available"`
	Permission   string          `json:"required_permission,omitempty"`
	Column       string          `json:"-"`
	Derived      string          `json:"-"`
	TagID        string          `json:"-"`
	TagKey       string          `json:"-"`
	MaxValue     uint64          `json:"-"`
}

func queryField(name, column string, kind QueryFieldType, summary bool, maxValue uint64) QueryField {
	ops := []QueryOperator{QueryEqual, QueryNotEqual, QueryIn, QueryNotIn}
	switch kind {
	case QueryAddress:
		ops = append(ops, QueryCIDR, QueryNotCIDR, QueryContains, QueryNotContains, QueryRegex, QueryNotRegex)
	case QueryText, QueryPrefix:
		ops = append(ops, QueryContains, QueryNotContains, QueryRegex, QueryNotRegex)
	case QueryUnsigned:
		ops = append(ops, QueryBetween, QueryNotBetween, QueryGreater, QueryLess, QueryBitAnd)
	case QueryTimestamp:
		ops = append(ops, QueryBetween, QueryNotBetween, QueryGreater, QueryLess)
	case QueryFlags:
		ops = append(ops, QueryHasAnyFlag, QueryHasNoFlag, QueryBitAnd, QueryContains, QueryNotContains, QueryRegex, QueryNotRegex)
	}
	return QueryField{Name: name, Column: column, Type: kind, LegacyHourly: summary, Raw: true, Rollup: true, MaxValue: maxValue, Operators: ops}
}

// Add a stored field here, with its storage mapping and bounds, rather than
// maintaining independent API, UI and model allowlists. Complete retained inputs
// support every field; legacy availability follows the actual older hourly shape.
var queryFieldRegistry = []QueryField{
	queryField("agent_id", "agent_id", QueryText, false, 0),
	queryField("exporter", "exporter", QueryText, true, 0),
	queryField("obs_domain", "obs_domain", QueryUnsigned, false, 1<<32-1),
	queryField("protocol", "protocol", QueryText, true, 0),
	queryField("ts", "ts", QueryTimestamp, false, 0),
	queryField("start_ts", "start_ts", QueryTimestamp, false, 0),
	queryField("src_addr", "src_addr", QueryAddress, true, 0),
	queryField("dst_addr", "dst_addr", QueryAddress, true, 0),
	queryField("src_port", "src_port", QueryUnsigned, false, 1<<16-1),
	queryField("dst_port", "dst_port", QueryUnsigned, false, 1<<16-1),
	queryField("transport", "transport", QueryText, true, 0),
	queryField("net_type", "net_type", QueryText, false, 0),
	queryField("in_if", "in_if", QueryUnsigned, false, 1<<32-1),
	queryField("out_if", "out_if", QueryUnsigned, false, 1<<32-1),
	queryField("vlan", "vlan", QueryUnsigned, false, 1<<16-1),
	queryField("tos", "tos", QueryUnsigned, false, 1<<8-1),
	queryField("tcp_flags", "tcp_flags", QueryUnsigned, false, 1<<8-1),
	queryField("next_hop", "next_hop", QueryAddress, false, 0),
	queryField("raw_bytes", "bytes", QueryUnsigned, false, ^uint64(0)),
	queryField("raw_packets", "packets", QueryUnsigned, false, ^uint64(0)),
	queryField("sampling", "sampling", QueryUnsigned, false, ^uint64(0)),
	queryField("bytes_scaled", "bytes_scaled", QueryUnsigned, true, ^uint64(0)),
	queryField("packets_scaled", "packets_scaled", QueryUnsigned, true, ^uint64(0)),
	queryField("src_asn", "src_asn", QueryUnsigned, false, 1<<32-1),
	queryField("src_as_name", "src_as_name", QueryText, false, 0),
	queryField("src_country", "src_country", QueryText, false, 0),
	queryField("dst_asn", "dst_asn", QueryUnsigned, false, 1<<32-1),
	queryField("dst_as_name", "dst_as_name", QueryText, false, 0),
	queryField("dst_country", "dst_country", QueryText, false, 0),
	queryField("row_id", "row_id", QueryText, true, 0),
}

func init() {
	for _, derived := range []struct {
		name, source string
		kind         QueryFieldType
		summary      bool
		max          uint64
	}{
		{"src_prefix", "src_addr", QueryPrefix, true, 0},
		{"dst_prefix", "dst_addr", QueryPrefix, true, 0},
		{"dscp", "tos", QueryUnsigned, false, 63},
		{"tcp_flag_names", "tcp_flags", QueryFlags, false, 255},
		{"in_if_name", "in_if", QueryText, false, 0},
		{"out_if_name", "out_if", QueryText, false, 0},
		{"in_if_role", "in_if", QueryText, false, 0},
		{"out_if_role", "out_if", QueryText, false, 0},
	} {
		field := queryField(derived.name, derived.source, derived.kind, derived.summary, derived.max)
		field.Derived = derived.name
		if derived.name == "in_if_name" || derived.name == "out_if_name" {
			field.Permission = "metrics.read"
		}
		if derived.name == "in_if_role" || derived.name == "out_if_role" {
			field.Permission = "entities.read"
		}
		queryFieldRegistry = append(queryFieldRegistry, field)
	}
	registerRoutingQueryFields()
}

// QueryFields returns independent metadata copies; a caller cannot mutate the
// process-wide validation vocabulary or another caller's schema.
func QueryFields() []QueryField {
	out := make([]QueryField, len(queryFieldRegistry))
	for i, field := range queryFieldRegistry {
		field.Operators = append([]QueryOperator(nil), field.Operators...)
		out[i] = field
	}
	return out
}

// LookupQueryField resolves only a canonical registry key. A user-provided name
// never becomes a column or expression in a storage statement.
func LookupQueryField(name string) (QueryField, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, field := range queryFieldRegistry {
		if field.Name == name {
			field.Operators = append([]QueryOperator(nil), field.Operators...)
			return field, true
		}
	}
	return QueryField{}, false
}
