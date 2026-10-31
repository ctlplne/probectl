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

func TestExplorerNestedSQLBindsEveryLiteralAndPreservesLogic(t *testing.T) {
	root := &flow.QueryFilterGroup{Match: "all", Groups: []flow.QueryFilterGroup{
		{Match: "any", Conditions: []flow.QueryPredicate{{Field: "dst_port", Op: flow.QueryBetween, Values: []string{"400", "500"}}, {Field: "src_as_name", Op: flow.QueryContains, Values: []string{"x' OR tenant_id!='' --"}}}},
		{Mode: "exclude", Conditions: []flow.QueryPredicate{{Field: "src_addr", Op: flow.QueryRegex, Values: []string{`^192\.0\.2\.`}}}},
	}}
	params := chParams{}
	sql, err := explorerFilterSQL(root, params)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, "x'") || strings.Contains(sql, "192\\") || !strings.Contains(sql, " OR ") || !strings.Contains(sql, " AND ") || !strings.Contains(sql, "NOT ") {
		t.Fatalf("lost Boolean tree or rendered literal SQL: %s", sql)
	}
	found := false
	for _, value := range params {
		if value == "x' OR tenant_id!='' --" {
			found = true
		}
	}
	if !found {
		t.Fatal("literal was dropped rather than bound")
	}
	// SQL-shaped tenant selection is never a registry key, even at inner depth.
	root.Groups[1].Conditions[0].Field = "tenant_id"
	if _, err := explorerFilterSQL(root, chParams{}); err == nil {
		t.Fatal("nested tenant selector compiled")
	}
	if _, err := explorerFilterSQL(&flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: "unknown"}}}, chParams{}); err == nil {
		t.Fatal("unresolved saved reference compiled as no filter")
	}
}

func TestExplorerD102OperatorCompilationUsesOnlyRegistryStructure(t *testing.T) {
	cases := []struct {
		field         string
		op            flow.QueryOperator
		value, syntax string
	}{
		{"src_as_name", flow.QueryContains, "TRANSIT", "positionCaseInsensitiveUTF8"},
		{"src_as_name", flow.QueryNotContains, "TRANSIT", "=0"},
		{"src_as_name", flow.QueryRegex, "^TRANSIT", "match("},
		{"src_as_name", flow.QueryNotRegex, "^TRANSIT", "NOT match("},
		{"raw_bytes", flow.QueryGreater, "9007199254740993", ">"},
		{"dst_port", flow.QueryLess, "1024", "<"},
		{"tcp_flags", flow.QueryBitAnd, "18", "bitAnd("},
		{"tcp_flag_names", flow.QueryBitAnd, "18", "bitAnd(tcp_flags,"},
	}
	for _, tc := range cases {
		t.Run(string(tc.op)+"/"+tc.field, func(t *testing.T) {
			predicates, err := flow.NormalizeQueryPredicates([]flow.QueryPredicate{{Field: tc.field, Op: tc.op, Values: []string{tc.value}}})
			if err != nil {
				t.Fatal(err)
			}
			params := chParams{}
			sql, err := explorerPredicateSQL(predicates[0], 0, params)
			if err != nil || !strings.Contains(sql, tc.syntax) || strings.Contains(sql, tc.value) {
				t.Fatalf("operator structure/literal binding: %s %v", sql, err)
			}
		})
	}
}
