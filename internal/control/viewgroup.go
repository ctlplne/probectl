// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"sort"
	"strings"
	"sync"
)

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

// DPR-109: a per-replica group name belongs to ONE process, so every restart
// and every rolling upgrade abandons a whole set of them, each holding the
// offsets it had committed. The broker keeps them until its offset retention
// expires (7 days by default), so they pile up — and because they never move
// again, every consumer-lag view reads them as huge, permanent backlogs.
// Recording what this process creates lets the sweep below tell an abandoned
// view group from a live one and from a SHARED durable group, which must never
// be touched: deleting a durable group's offsets would replay its side effects.
var (
	viewGroupMu    sync.Mutex
	viewGroupBases = map[string]struct{}{}
	viewGroupOwn   = map[string]struct{}{}
)

// viewGroup returns the per-replica consumer group for a pure in-RAM view
// (base when no instance id is set — single replica / tests).
func viewGroup(base string) string {
	name := base
	if instanceGroupSuffix != "" {
		name = base + "-" + instanceGroupSuffix
	}
	viewGroupMu.Lock()
	viewGroupBases[base] = struct{}{}
	viewGroupOwn[name] = struct{}{}
	viewGroupMu.Unlock()
	return name
}

// viewGroupPrefixes returns the recorded base names and this process's own
// group names, both sorted for deterministic logs and tests.
func viewGroupPrefixes() (bases, own []string) {
	viewGroupMu.Lock()
	defer viewGroupMu.Unlock()
	for b := range viewGroupBases {
		bases = append(bases, b)
	}
	for o := range viewGroupOwn {
		own = append(own, o)
	}
	sort.Strings(bases)
	sort.Strings(own)
	return bases, own
}

// abandonedViewGroup reports whether an EMPTY consumer group is a view group
// left behind by a process that is gone.
//
// A group qualifies only when it sits under a recorded view base AND carries an
// instance segment: pipeline lanes append "-t-<tenant>", so "<base>-t-<tenant>"
// is the shared-name form a single-replica deployment uses (bounded, and not
// distinguishable from a durable group by name alone) and is left alone. This
// process's own groups are excluded so a rebalance window never deletes them.
func abandonedViewGroup(group string, bases, own []string) bool {
	for _, o := range own {
		if group == o || strings.HasPrefix(group, o+"-t-") {
			return false
		}
	}
	for _, b := range bases {
		if !strings.HasPrefix(group, b+"-") {
			continue
		}
		if strings.HasPrefix(group, b+"-t-") {
			continue
		}
		return true
	}
	return false
}
