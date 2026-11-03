// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestPrefixTagSQLRetainsFullPredicateReachWithoutRepeatedRangeChecks(t *testing.T) {
	tenant, contextID := uuid.NewString(), uuid.NewString()
	data, err := NewTagQueryData(tenant, 1, []tags.Definition{{TenantID: tenant, ID: uuid.NewString(), Key: "customer"}}, []tags.ExporterProjection{{Exporter: "192.0.2.10", ContextID: contextID}}, 1<<20, TagQuerySources{Prefixes: []tags.PrefixProjection{{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, ID: uuid.NewString(), Network: netip.MustParsePrefix("10.0.0.0/8"), Values: map[string]string{"customer": "source"}}}})
	if err != nil {
		t.Fatal(err)
	}
	filter := &flow.QueryFilterGroup{Match: "all"}
	for group := 0; group < 4; group++ {
		child := flow.QueryFilterGroup{Match: "any"}
		for i := 0; i < 250; i++ {
			field := []string{"tag.src_prefix.customer", "tag.dst_prefix.customer"}[i%2]
			child.Conditions = append(child.Conditions, flow.QueryPredicate{Field: field, Op: flow.QueryEqual, Values: []string{"literal-p" + strconv.Itoa(group*250+i)}})
		}
		filter.Groups = append(filter.Groups, child)
	}
	plan := flow.QueryPlan{From: time.Now().Add(-time.Hour), To: time.Now(), GroupBy: []string{"tag.src_prefix.customer"}, MatrixWith: []string{"tag.dst_prefix.customer"}, View: "matrix", Filter: filter, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	sql, params, err := planSQLWithTags(DefaultExplorerBudget(), plan, "probectl_flows", nil, tenant, data)
	if err != nil {
		t.Fatalf("full prefix predicate reach was narrowed: %v", err)
	}
	if len(sql) >= 256<<10 {
		t.Fatalf("prefix range checking expanded the parser envelope: %d bytes", len(sql))
	}
	bound, keys := 0, 0
	for name := range params {
		if strings.HasPrefix(name, "filter_") {
			bound++
		}
		if strings.HasPrefix(name, "tag_key_") {
			keys++
		}
	}
	if bound != 1000 || keys != 2 || strings.Contains(sql, "literal-p") || strings.Contains(sql, "customer") {
		t.Fatal("prefix sides collapsed, predicates dropped or metadata entered SQL structure")
	}
}
