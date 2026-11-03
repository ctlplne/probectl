// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func TestPlanSQLCanonicalAddressesRetainFullPredicateReach(t *testing.T) {
	filter := &flow.QueryFilterGroup{Match: "all"}
	for group := 0; group < 4; group++ {
		child := flow.QueryFilterGroup{Match: "any"}
		for i := 0; i < 250; i++ {
			child.Conditions = append(child.Conditions, flow.QueryPredicate{Field: "src_addr", Op: flow.QueryEqual, Values: []string{fmt.Sprintf("2001:db8::%x", 1+group*250+i)}})
		}
		filter.Groups = append(filter.Groups, child)
	}
	plan := flow.QueryPlan{From: time.Now().Add(-time.Hour), To: time.Now(), GroupBy: []string{"src_addr", "dst_addr", "exporter"}, Filter: filter, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	sql, params, err := planSQL(plan, "probectl_flows", nil)
	if err != nil {
		t.Fatalf("full address predicate reach was narrowed: %v", err)
	}
	if len(sql) >= 256<<10 {
		t.Fatalf("canonical formatting expanded SQL beyond the existing parser envelope: %d bytes", len(sql))
	}
	bound := 0
	for name := range params {
		if strings.HasPrefix(name, "filter_") {
			bound++
		}
	}
	if bound != 1000 || strings.Contains(sql, "2001:db8") {
		t.Fatal("address conditions were dropped or interpolated instead of bound")
	}
}
