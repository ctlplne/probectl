// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otel

import (
	"strings"
	"testing"
)

func TestFlowExplorerMetricNamesStayBoundedAndDistinctFromDatabase(t *testing.T) {
	seen := map[string]bool{}
	for _, operation := range FlowExplorerOperations() {
		names, ok := FlowExplorerMetrics(operation)
		if !ok {
			t.Fatal("known operation is not mapped")
		}
		for _, name := range []string{names.Operations, names.Duration, names.Active} {
			if !strings.HasPrefix(name, "probectl.flow.explorer.") || seen[name] {
				t.Fatal("invalid or duplicate application metric")
			}
			seen[name] = true
		}
	}
	for _, bad := range []string{"", "tenant-private", "SELECT private", "query\n"} {
		if _, ok := FlowExplorerMetrics(bad); ok {
			t.Fatal("untrusted value became a metric name")
		}
	}
	first := FlowExplorerDurationBuckets()
	first[0] = 100
	if FlowExplorerDurationBuckets()[0] != 0.001 {
		t.Fatal("caller mutated global metric buckets")
	}
}
