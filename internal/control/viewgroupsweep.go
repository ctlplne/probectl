// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"log/slog"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/metrics"
)

// metricViewGroupsSwept counts the abandoned view groups this instance deleted
// (DPR-109). The sweep interval is PROBECTL_VIEW_GROUP_SWEEP.
const metricViewGroupsSwept = "probectl_view_groups_swept_total"

// RunViewGroupSweep periodically deletes the per-replica view consumer groups
// that no process is consuming any more.
//
// Every replica builds its in-RAM views through a consumer group named after
// itself (ARCH-003), so a rolling upgrade of three replicas abandons three full
// sets of them — one per view lane per tenant — and each one keeps the offsets
// it had committed. The broker holds them until its offset retention expires
// (7 days by default), so on a busy MSP install the group list is dominated by
// dead groups, and because their offsets never move again, consumer-lag
// dashboards and alerts read them as enormous permanent backlogs. Sweeping is
// safe for exactly the reason these groups are per-replica in the first place:
// they carry no side effects, and a fresh process rebuilds its view from the
// start of the stream regardless of what was committed.
//
// SHARED durable groups are never touched (deleting their offsets would replay
// their side effects), which is why only groups under a recorded view base with
// an instance segment qualify, and only while the broker reports them EMPTY.
// The sweep is best-effort: a bus that cannot introspect groups, a broker that
// refuses, or a group that gained a member since it was listed all leave the
// control plane running and simply try again next tick.
func RunViewGroupSweep(ctx context.Context, b bus.Bus, every time.Duration, reg *metrics.Registry, log *slog.Logger) {
	janitor, ok := b.(bus.GroupJanitor)
	if !ok || every <= 0 {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweepViewGroups(ctx, janitor, reg, log)
		}
	}
}

func sweepViewGroups(ctx context.Context, janitor bus.GroupJanitor, reg *metrics.Registry, log *slog.Logger) {
	bases, own := viewGroupPrefixes()
	if len(bases) == 0 {
		return
	}
	empty, err := janitor.ListEmptyGroups(ctx)
	if err != nil {
		log.Warn("view group sweep could not list consumer groups", "error", err)
		return
	}
	var stale []string
	for _, g := range empty {
		if abandonedViewGroup(g, bases, own) {
			stale = append(stale, g)
		}
	}
	if len(stale) == 0 {
		return
	}
	deleted, err := janitor.DeleteGroups(ctx, stale)
	if len(deleted) > 0 {
		if reg != nil {
			reg.Counter(metricViewGroupsSwept, "view consumer groups deleted because no process was consuming them").Add(uint64(len(deleted)))
		}
		log.Info("deleted abandoned view consumer groups",
			"deleted", len(deleted), "candidates", len(stale))
	}
	if err != nil {
		log.Warn("view group sweep was refused", "error", err)
	}
}
