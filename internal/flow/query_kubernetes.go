// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"slices"
	"strings"
)

var kubernetesQueryDimensions = []string{"cluster", "namespace", "pod", "pod_uid", "workload", "workload_uid", "service", "service_uid"}

// KubernetesQueryField identifies only registered endpoint metadata. Raw
// clock provenance and entity source authorization are checked by the store.
func KubernetesQueryField(name string) (side, dimension string, ok bool) {
	side, dimension, split := strings.Cut(name, "_k8s_")
	return side, dimension, split && (side == "src" || side == "dst") && slices.Contains(kubernetesQueryDimensions, dimension)
}

func registerKubernetesQueryFields() {
	for _, side := range []string{"src", "dst"} {
		for _, dimension := range kubernetesQueryDimensions {
			field := queryField(side+"_k8s_"+dimension, "routing_capture_key", QueryText, false, 0)
			field.Derived, field.Permission, field.Rollup = "flow_kubernetes", "entities.read", false
			queryFieldRegistry = append(queryFieldRegistry, field)
		}
	}
}

// PlanUsesKubernetes also checks both matrix axes and nested, expanded
// filters. Saved filter references must have been resolved by the caller.
func PlanUsesKubernetes(plan QueryPlan) bool {
	for _, names := range [][]string{plan.GroupBy, plan.MatrixWith, QueryFilterFields(plan.Filter)} {
		for _, name := range names {
			if _, _, ok := KubernetesQueryField(name); ok {
				return true
			}
		}
	}
	return false
}
