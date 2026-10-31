// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/flow"
)

func parseQuestionFilter(t *testing.T, question string) (*flow.QueryFilterGroup, int, error) {
	t.Helper()
	budget := DefaultFlowQuestionBudget()
	tokens, err := lexFlowQuestion(t.Context(), question, budget)
	if err != nil {
		return nil, 0, err
	}
	cursor := questionCursor{ctx: t.Context(), tokens: tokens, vocabulary: newFlowQuestionVocabulary(), budget: budget}
	result, err := cursor.filter()
	return result, cursor.position, err
}

func questionPredicateValues(field flow.QueryField, operator flow.QueryOperator) []string {
	switch operator {
	case flow.QueryContains, flow.QueryNotContains:
		return []string{"literal"}
	case flow.QueryRegex, flow.QueryNotRegex:
		return []string{"^.*$"}
	case flow.QueryCIDR, flow.QueryNotCIDR:
		return []string{"192.0.2.0/24"}
	case flow.QueryBitAnd:
		return []string{"2"}
	}
	value, upper := "literal", "second"
	switch field.Type {
	case flow.QueryAddress:
		value, upper = "192.0.2.1", "192.0.2.2"
	case flow.QueryPrefix:
		value, upper = "192.0.2.0/24", "198.51.100.0/24"
	case flow.QueryUnsigned:
		value, upper = "1", "2"
	case flow.QueryTimestamp:
		value, upper = "2026-01-01T00:00:00.123456789Z", "2026-01-02T00:00:00.123456789Z"
	case flow.QueryFlags:
		value, upper = "SYN", "ACK"
	}
	if operator == flow.QueryBetween || operator == flow.QueryNotBetween {
		return []string{value, upper}
	}
	return []string{value}
}

func TestFlowQuestionFiltersCoverEveryRegisteredFieldOperator(t *testing.T) {
	for _, field := range flow.QueryFields() {
		for _, operator := range field.Operators {
			values := questionPredicateValues(field, operator)
			var quoted []string
			for _, value := range values {
				quoted = append(quoted, strconv.Quote(value))
			}
			question := field.Name + " " + string(operator) + " (" + strings.Join(quoted, ",") + ")"
			group, position, err := parseQuestionFilter(t, question)
			if err != nil || position == 0 || len(group.Conditions) != 1 || group.Conditions[0].Field != field.Name || group.Conditions[0].Op != operator {
				t.Fatal("registered predicate could not pass question grammar", field.Name, operator, err)
			}
		}
	}
}

func TestFlowQuestionFiltersPreservePrecedenceAndExclusion(t *testing.T) {
	for _, tc := range []struct {
		question string
		rows     []map[string]string
		want     []bool
	}{
		{`src_port equals 443 or src_port equals 80 and dst_port equals 8080`, []map[string]string{{"src_port": "443", "dst_port": "1"}, {"src_port": "80", "dst_port": "1"}, {"src_port": "80", "dst_port": "8080"}}, []bool{true, false, true}},
		{`all of(any of(src_port equals 443, src_port equals 80), exclude(dst_country equals "US"))`, []map[string]string{{"src_port": "443", "dst_country": "US"}, {"src_port": "80", "dst_country": "DE"}, {"src_port": "8080", "dst_country": "DE"}}, []bool{false, true, false}},
		{`not not src_port equals 443`, []map[string]string{{"src_port": "443"}, {"src_port": "80"}}, []bool{true, false}},
	} {
		group, _, err := parseQuestionFilter(t, tc.question)
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := flow.PrepareQueryFilter(group)
		if err != nil {
			t.Fatal(err)
		}
		for index, row := range tc.rows {
			if got := compiled.Matches(func(key string) string { return row[key] }); got != tc.want[index] {
				t.Fatal("natural expression changed boolean meaning", tc.question, index, got)
			}
		}
	}
}

func TestFlowQuestionFiltersPackFullReachWithoutChangingMeaning(t *testing.T) {
	var clauses []string
	for i := 0; i < flow.MaxQueryPredicates; i++ {
		clauses = append(clauses, fmt.Sprintf("src_port eq %d", i))
	}
	question := "exclude(any of(" + strings.Join(clauses, ",") + "))"
	group, _, err := parseQuestionFilter(t, question)
	if err != nil {
		t.Fatal("full native condition reach narrowed", err)
	}
	compiled, err := flow.PrepareQueryFilter(group)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Matches(func(string) string { return "999" }) || !compiled.Matches(func(string) string { return "1001" }) {
		t.Fatal("packing moved exclusion into individual conditions")
	}
	question = strings.Join(append(clauses, "src_port eq 1000"), " or ")
	if _, _, err := parseQuestionFilter(t, question); !errors.Is(err, errQuestionClause) {
		t.Fatal("expanded guard exceeded", err)
	}
}

func TestFlowQuestionFiltersKeepLiteralsAndRequireScopedSavedResolution(t *testing.T) {
	group, _, err := parseQuestionFilter(t, `raw_bytes gt 18446744073709551615 and src_as_name eq "DROP TABLE users; tenant_id=other"`)
	if err != nil || group.Conditions[0].Values[0] != "18446744073709551615" || group.Conditions[1].Values[0] != "DROP TABLE users; tenant_id=other" {
		t.Fatal("literal became an expression or lost integer precision", err)
	}
	group, _, err = parseQuestionFilter(t, `source port in port range 443-445 and saved filter "owned-ref"`)
	if err != nil || len(group.Conditions) != 1 || group.Conditions[0].Values[1] != "445" || len(group.Saved) != 1 || group.Saved[0].ID != "owned-ref" {
		t.Fatal("typed range/reference lost", err)
	}
	if _, err := flow.PrepareQueryFilter(group); err == nil {
		t.Fatal("planner bypassed tenant-scoped saved-filter resolution")
	}
	for _, question := range []string{`tenant_id eq other`, `src_port eq 65536`, `raw_bytes eq 18446744073709551616`, `src_port regex "x"`, `src_addr in subnet "not-prefix"`} {
		if _, _, err := parseQuestionFilter(t, question); err == nil {
			t.Fatal("invalid field/type/operator accepted", question)
		}
	}
	question := "src_port eq 1"
	for i := 0; i < 7; i++ {
		operator := "and"
		if i%2 == 0 {
			operator = "or"
		}
		question = "(" + question + " " + operator + " src_port eq " + strconv.Itoa(i+2) + ")"
	}
	if _, _, err := parseQuestionFilter(t, question); err == nil {
		t.Fatal("semantic group depth guard exceeded")
	}
}
