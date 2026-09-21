// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

// Permission keys gating each query domain after the tenant boundary. A caller
// must hold the RBAC permission and pass the configured ABAC deny-override or
// the query fails closed.
const (
	PermMetricsRead  = "metrics.read"
	PermEventsRead   = "events.read"
	PermEntitiesRead = "entities.read"
	PermTopologyRead = "topology.read"
)

func permissionFor(d Domain) string {
	switch d {
	case DomainMetrics:
		return PermMetricsRead
	case DomainEvents:
		return PermEventsRead
	case DomainEntities:
		return PermEntitiesRead
	case DomainTopology:
		return PermTopologyRead
	default:
		return ""
	}
}
