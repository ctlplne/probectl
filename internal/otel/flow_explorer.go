// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otel

// FlowExplorerMetricSet defines application-service instruments, not database
// client durations or scanned-byte measurements. Duration uses UCUM s; discrete
// operation counts/active work use {operation}. See docs/otel-mapping.md.
type FlowExplorerMetricSet struct {
	Operations string
	Duration   string
	Active     string
}

// FlowExplorerOperations returns the fixed service boundaries shared by every
// transport. Internal comparison/coverage passes do not become extra queries.
func FlowExplorerOperations() []string {
	return []string{"plan", "query", "comparison", "page", "comparison_page", "csv_prepare"}
}

// FlowExplorerOutcomes is a fixed cardinality set, never dependency error text.
// A Prometheus outcome label maps to probectl.flow.explorer.outcome in OTel.
func FlowExplorerOutcomes() []string {
	return []string{"success", "validation", "budget", "coverage", "canceled", "unavailable", "authorization"}
}

// FlowExplorerMetrics maps code-owned service names to the OTel namespace.
// Unknown or caller-supplied names cannot create instrument/label cardinality.
func FlowExplorerMetrics(operation string) (FlowExplorerMetricSet, bool) {
	switch operation {
	case "plan", "query", "comparison", "page", "comparison_page", "csv_prepare":
		prefix := "probectl.flow.explorer." + operation
		return FlowExplorerMetricSet{Operations: prefix + ".operations", Duration: prefix + ".duration", Active: prefix + ".active"}, true
	default:
		return FlowExplorerMetricSet{}, false
	}
}

// FlowExplorerDurationBuckets are fixed seconds; counts are retained rather
// than unbounded request samples. +Inf is supplied by histogram exposition.
func FlowExplorerDurationBuckets() []float64 {
	return []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60}
}
