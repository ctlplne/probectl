// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

// ARCH-003: replica-coherent serving for the in-RAM read views.
//
// The topology graph, the latest-result view, and the endpoint view are built
// by consuming the bus into a process-local structure. With a SHARED consumer
// group across replicas, Kafka partitions the messages BETWEEN replicas, so
// each replica sees only a slice of the stream and answers the same query
// differently depending on which replica a load balancer hits — the
// incoherence documented in docs/ha.md.
//
// These views are PURE read models with NO external side effects (no incidents,
// no SIEM, no DLQ), so the safe fix is per-replica fan-in: give each replica a
// UNIQUE consumer group for these views, so every replica consumes the ENTIRE
// stream and builds the COMPLETE view. Any replica then answers identically.
// (Consumers that have side effects — NDR/IOC incident raising, SIEM export,
// the durable result/flow/device pipelines — MUST keep their shared groups, or
// per-replica fan-in would duplicate those effects. Only pure views get this.)
//
// instanceGroupSuffix is the per-process identity appended to a pure-view
// consumer group. Empty (single replica / not set) keeps the original shared
// group name, so single-replica deployments and tests are unchanged.
var instanceGroupSuffix string

// SetInstanceGroupSuffix records this control-plane instance's unique id so the
// pure-view consumers fan in per replica (ARCH-003). Call once at startup with
// a value unique per replica (e.g. a boot UUID).
func SetInstanceGroupSuffix(id string) { instanceGroupSuffix = id }

// viewGroup returns the per-replica consumer group for a pure in-RAM view
// (base when no instance id is set — single replica / tests).
func viewGroup(base string) string {
	if instanceGroupSuffix == "" {
		return base
	}
	return base + "-" + instanceGroupSuffix
}
