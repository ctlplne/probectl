// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
