// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/flow"
)

func TestRoutingASNFiltersBindUnknownSeparatelyFromZeroAndKeepExclusions(t *testing.T) {
	for _, op := range []flow.QueryOperator{flow.QueryEqual, flow.QueryNotEqual, flow.QueryIn, flow.QueryNotIn, flow.QueryGreater, flow.QueryLess, flow.QueryBetween, flow.QueryNotBetween, flow.QueryBitAnd} {
		values := []string{"0"}
		switch op {
		case flow.QueryEqual, flow.QueryNotEqual:
			values = []string{""}
		case flow.QueryIn, flow.QueryNotIn:
			values = []string{"", "0", "4294967295"}
		case flow.QueryBetween, flow.QueryNotBetween:
			values = []string{"0", "4294967295"}
		}
		predicates, err := flow.NormalizeQueryPredicates([]flow.QueryPredicate{{Field: "src_bgp_origin_as", Op: op, Values: values}})
		if err != nil {
			t.Fatal("routing ASN filter refused unknown or full-width values", op, err)
		}
		params := chParams{}
		sql, err := explorerPredicateSQL(predicates[0], 0, params)
		if err != nil || !strings.HasPrefix(sql, "ifNull(") || !strings.HasSuffix(sql, ",0)") || strings.Contains(sql, "4294967295") {
			t.Fatal("routing SQL lost bound values or two-valued nested exclusion", op, sql, err)
		}
		exact := op == flow.QueryEqual || op == flow.QueryNotEqual || op == flow.QueryIn || op == flow.QueryNotIn
		if strings.Contains(sql, "ifNull(toString(toUInt32OrNull(") != exact {
			t.Fatal("routing SQL merged ASN zero with unknown or compared numeric ranges as text", op, sql)
		}
		for key, value := range params {
			if strings.HasPrefix(key, "filter_") && value == "" && strings.Contains(sql, "{"+key+":UInt64}") {
				t.Fatal("unknown routing ASN was bound as an invalid numeric literal", op)
			}
		}
	}
}
